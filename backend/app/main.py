import logging
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from detection_engine import analyze
from .models import APIKey, Database, Scan, ScanFinding, Subscription, User
from .schemas import APIKeyCreated, APIKeyRequest, APIKeyResponse, LoginRequest, RegisterRequest, ScanRequest, ScanResponse, ThreatIntelligenceResponse, TokenResponse, UserResponse
from .security import create_access_token, hash_api_key, hash_password, hash_scan_input, read_access_token, verify_password
from .threat_intel import ThreatLookup, lookup_url, prepare_url

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("scamshield")
database = Database(settings.database_url)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])
bearer = HTTPBearer(auto_error=False)

app = FastAPI(title="ScamShield API", version="1.0.0", description="Transparent heuristic checks for suspicious URLs and messages, with optional Google Web Risk lookups for website-link scans.")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def startup() -> None:
    if len(os.getenv("JWT_SECRET", "")) < 32 or os.getenv("JWT_SECRET") == "replace-with-a-long-random-secret":
        raise RuntimeError("Set JWT_SECRET to a unique random value before starting the API")
    database.create_tables()


def get_db():
    session = database.session_factory()
    try:
        yield session
    finally:
        session.close()


DbSession = Annotated[Session, Depends(get_db)]


def optional_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: DbSession,
) -> User | None:
    if credentials is None:
        return None
    credential = credentials.credentials
    if credential.startswith("ss_live_"):
        api_key = db.scalar(select(APIKey).where(APIKey.key_hash == hash_api_key(credential)))
        if api_key is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
        return db.get(User, api_key.user_id)
    user_id = read_access_token(credential)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired credentials")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired credentials")
    return user


def require_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: DbSession,
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if credentials.credentials.startswith("ss_live_"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="A user session is required for account management")
    user_id = read_access_token(credentials.credentials)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired credentials")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired credentials")
    return user


@app.get("/health", tags=["system"])
def health():
    external_intelligence = bool(os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip())
    return {
        "status": "ok",
        "detection_mode": "hybrid" if external_intelligence else "heuristic",
        "external_intelligence": external_intelligence,
        "external_provider": "google_web_risk" if external_intelligence else None,
        "model_configured": False,
    }


@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201, tags=["authentication"])
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterRequest, db: DbSession):
    email = str(payload.email).lower()
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.flush()
        db.add(Subscription(user_id=user.id, plan="free", status="active", monthly_limit=int(os.getenv("FREE_MONTHLY_LIMIT", "25"))))
        db.commit()
        db.refresh(user)
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists") from error
    return user


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["authentication"])
@limiter.limit("10/minute")
def login(request: Request, payload: LoginRequest, db: DbSession):
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token, expires_in = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in=expires_in)


@app.get("/api/v1/auth/me", response_model=UserResponse, tags=["authentication"])
def me(user: Annotated[User, Depends(require_user)]):
    return user


@app.post("/api/v1/scans", response_model=ScanResponse, tags=["scans"])
@limiter.limit(settings.rate_limit)
def create_scan(request: Request, payload: ScanRequest, db: DbSession, user: Annotated[User | None, Depends(optional_user)]):
    if user is not None:
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        subscription = db.scalar(select(Subscription).where(Subscription.user_id == user.id))
        monthly_limit = subscription.monthly_limit if subscription else int(os.getenv("FREE_MONTHLY_LIMIT", "25"))
        scan_count = db.scalar(select(func.count(Scan.id)).where(Scan.user_id == user.id, Scan.scanned_at >= month_start)) or 0
        if scan_count >= monthly_limit:
            raise HTTPException(status_code=429, detail="Monthly scan limit reached for this plan")
    content = payload.input
    live_lookup = ThreatLookup(
        provider=None,
        status="not_checked" if payload.scan_type != "url" else "skipped",
        threat_types=[],
        message=(
            "Live URL reputation checks are only used for website-link scans."
            if payload.scan_type != "url"
            else "This link was not sent to Google; only local heuristic checks were used."
        ),
    )
    if payload.share_with_google and payload.scan_type != "url":
        raise HTTPException(status_code=422, detail="Google Web Risk lookups are only available for website-link scans")
    if payload.scan_type == "url":
        try:
            content, url_to_check, skip_reason = prepare_url(payload.input)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        if payload.share_with_google and url_to_check:
            live_lookup = lookup_url(url_to_check)
        elif payload.share_with_google and skip_reason:
            live_lookup = ThreatLookup("google_web_risk", "skipped", [], skip_reason)

    try:
        analysis = analyze(payload.scan_type, content)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    findings = [
        {"code": finding.code, "title": finding.title, "detail": finding.detail, "severity": finding.severity}
        for finding in analysis.findings
    ]
    risk_score = analysis.risk_score
    risk_level = analysis.risk_level
    explanation = analysis.explanation
    detection_mode = "hybrid" if live_lookup.status in {"matched", "clear"} else "heuristic"
    if live_lookup.status == "matched":
        findings.append({
            "code": "google_web_risk_match",
            "title": "Google Web Risk match",
            "detail": f"This link matched Google Web Risk threat lists: {', '.join(live_lookup.threat_types)}.",
            "severity": "high",
        })
        risk_score = max(risk_score, 90)
        risk_level = "high"
        explanation = f"{explanation} Google Web Risk reported a threat-list match."

    scan = Scan(
        user_id=user.id if user else None,
        scan_type=payload.scan_type,
        risk_score=risk_score,
        risk_level=risk_level,
        input_digest=hash_scan_input(payload.input),
        explanation=explanation,
        scanned_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()
    for finding in findings:
        db.add(ScanFinding(scan_id=scan.id, **finding))
    db.commit()
    logger.info("scan completed id=%s type=%s score=%s mode=%s", scan.id, payload.scan_type, risk_score, detection_mode)
    return ScanResponse(
        id=scan.id, scan_type=payload.scan_type, risk_score=risk_score,
        risk_level=risk_level, explanation=explanation, findings=findings,
        recommendations=analysis.recommendations,
        scanned_at=scan.scanned_at, detection_mode=detection_mode,
        threat_intelligence=ThreatIntelligenceResponse(
            provider=live_lookup.provider,
            status=live_lookup.status,
            threat_types=live_lookup.threat_types,
            message=live_lookup.message,
        ),
    )


@app.get("/api/v1/scans", response_model=list[ScanResponse], tags=["scans"])
def scan_history(user: Annotated[User, Depends(require_user)], db: DbSession, limit: int = 50):
    limit = min(max(limit, 1), 100)
    scans = db.scalars(select(Scan).where(Scan.user_id == user.id).order_by(Scan.scanned_at.desc()).limit(limit)).all()
    rows = []
    for scan in scans:
        rows.append(ScanResponse(
            id=scan.id, scan_type=scan.scan_type, risk_score=scan.risk_score, risk_level=scan.risk_level,
            explanation=scan.explanation,
            findings=[{"code": f.code, "title": f.title, "detail": f.detail, "severity": f.severity} for f in scan.findings],
            recommendations=["Verify the sender through an independent channel.", "Do not share passwords, payment details, or one-time codes."],
            scanned_at=scan.scanned_at, detection_mode="heuristic",
        ))
    return rows


@app.post("/api/v1/api-keys", response_model=APIKeyCreated, status_code=201, tags=["API keys"])
@limiter.limit("10/hour")
def create_api_key(request: Request, payload: APIKeyRequest, user: Annotated[User, Depends(require_user)], db: DbSession):
    raw_key = "ss_live_" + secrets.token_urlsafe(32)
    record = APIKey(user_id=user.id, name=payload.name, prefix=raw_key[:16], key_hash=hash_api_key(raw_key))
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info("api key created user_id=%s key_id=%s", user.id, record.id)
    return APIKeyCreated(id=record.id, name=record.name, prefix=record.prefix, created_at=record.created_at, key=raw_key)


@app.get("/api/v1/api-keys", response_model=list[APIKeyResponse], tags=["API keys"])
def list_api_keys(user: Annotated[User, Depends(require_user)], db: DbSession):
    return db.scalars(select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())).all()


@app.delete("/api/v1/api-keys/{key_id}", status_code=204, tags=["API keys"])
def delete_api_key(key_id: str, user: Annotated[User, Depends(require_user)], db: DbSession):
    try:
        uuid.UUID(key_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail="API key not found") from error
    record = db.scalar(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id))
    if record is None:
        raise HTTPException(status_code=404, detail="API key not found")
    db.delete(record)
    db.commit()


@app.exception_handler(Exception)
async def unhandled_error(request: Request, error: Exception):
    logger.exception("request failed method=%s path=%s", request.method, request.url.path)
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=500, content={"detail": "An unexpected server error occurred"})
