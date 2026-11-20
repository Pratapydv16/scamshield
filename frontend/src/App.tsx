import { useState, type FormEvent } from "react";
import {
  Check, Clock3, CreditCard, Link2, LockKeyhole, Mail,
  MessageSquareText, Shield, ShieldAlert, ShieldCheck, Sparkles, X,
} from "lucide-react";

type ScanKind = "url" | "email" | "sms" | "payment";
type ThreatIntelligence = {
  provider: "google_web_risk" | null;
  status: "not_checked" | "not_configured" | "skipped" | "matched" | "clear" | "error";
  threat_types: string[];
  message: string;
};
type Result = {
  score: number;
  level: string;
  indicators: string[];
  explanation: string;
  recommendations: string[];
  created_at: string;
  mode: "heuristic" | "hybrid" | "demo";
  threat_intelligence?: ThreatIntelligence;
};

const API = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "http://localhost:8000/api/v1" : "");
const scanTypes: { id: ScanKind; label: string; icon: typeof Link2; placeholder: string }[] = [
  { id: "url", label: "Website link", icon: Link2, placeholder: "Paste a suspicious website link…" },
  { id: "email", label: "Email", icon: Mail, placeholder: "Paste the email text or headers…" },
  { id: "sms", label: "Text message", icon: MessageSquareText, placeholder: "Paste a suspicious SMS or chat message…" },
  { id: "payment", label: "Payment request", icon: CreditCard, placeholder: "Describe the payment request…" },
];

function demoResult(): Result {
  return {
    score: 74,
    level: "high",
    indicators: ["Urgency or pressure language", "Potential credential or payment request", "Unverified sender or destination"],
    explanation: "This is a simulated example, not a live threat-intelligence check or a definitive security verdict.",
    recommendations: [
      "Verify the sender using a separate, trusted channel.",
      "Do not share passwords, payment details, or one-time codes.",
      "Open websites from a saved bookmark instead of message links.",
    ],
    created_at: new Date().toISOString(),
    mode: "demo",
  };
}

function Brand() {
  return <div className="brand"><div className="brand-mark"><Shield size={18} strokeWidth={2.2} /></div><span>scam<span className="brand-accent">shield</span><sup> AI</sup></span></div>;
}

function ScanForm({ onResult }: { onResult: (result: Result | null) => void }) {
  const [kind, setKind] = useState<ScanKind>("url");
  const [input, setInput] = useState("");
  const [demo, setDemo] = useState(false);
  const [shareWithGoogle, setShareWithGoogle] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const activeType = scanTypes.find((type) => type.id === kind)!;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    const content = input.trim();
    if (!content) {
      setError("Paste or enter something to check first.");
      return;
    }
    if (content.length > 10_000) {
      setError("Keep your submission under 10,000 characters.");
      return;
    }

    onResult(null);
    setLoading(true);
    try {
      if (demo) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        onResult(demoResult());
        return;
      }

      if (!API) throw new Error("Scanner API is not configured. Set VITE_API_URL to the deployed API base URL.");
      const response = await fetch(`${API}/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_type: kind, input: content, share_with_google: shareWithGoogle }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "The check could not be completed.");

      onResult({
        score: data.risk_score,
        level: data.risk_level,
        indicators: data.findings.map((item: { title: string; detail: string }) => `${item.title}: ${item.detail}`),
        explanation: data.explanation,
        recommendations: data.recommendations,
        created_at: data.scanned_at,
        mode: data.detection_mode,
        threat_intelligence: data.threat_intelligence,
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not reach the scanner. Check the API connection or choose demo mode.");
    } finally {
      setLoading(false);
    }
  }

  return <form className="scan-box simple-scan-box" onSubmit={submit}>
    <div className="scan-tabs" role="group" aria-label="Choose what to check">
      {scanTypes.map((type) => <button
        key={type.id}
        type="button"
        aria-pressed={kind === type.id}
        className={`scan-tab ${kind === type.id ? "selected" : ""}`}
        onClick={() => { setKind(type.id); setShareWithGoogle(false); }}
      ><type.icon size={16}/><span>{type.label}</span></button>)}
    </div>
    <label className="sr-only" htmlFor="scan-input">{activeType.label} to check</label>
    <textarea
      id="scan-input"
      value={input}
      onChange={(event) => setInput(event.target.value)}
      placeholder={activeType.placeholder}
      maxLength={10_000}
      rows={5}
    />
    <div className="scan-bottom">
      <div className="scan-assurance"><LockKeyhole size={13}/><span>Raw input not retained</span><span className="assurance-dot"/><span>{input.length}/10,000</span></div>
      <button className="button button-primary scan-submit" type="submit" disabled={loading}>
        {loading ? <><span className="spinner"/> Checking</> : <><Sparkles size={15}/> Check for warning signs</>}
      </button>
    </div>
    <div className="scan-demo">
      <label><input type="checkbox" checked={demo} onChange={(event) => setDemo(event.target.checked)}/> Use simulated demo result</label>
      <span>Demo results are simulated</span>
    </div>
    {kind === "url" && <label className="google-consent">
      <input type="checkbox" checked={shareWithGoogle} onChange={(event) => setShareWithGoogle(event.target.checked)}/>
      <span>Optional: send this URL to Google Web Risk for a reputation check. The full link, including its path and query, will be shared.</span>
    </label>}
    <p className="scan-provider-note">Email, message, and payment text are not sent to Google. A live lookup requires the service to be configured.</p>
    {error && <p className="form-error" role="alert">{error}</p>}
  </form>;
}

function ResultCard({ result, onClose }: { result: Result; onClose: () => void }) {
  const riskClass = result.level.toLowerCase() === "high" ? "high" : result.level.toLowerCase() === "elevated" ? "medium" : "low";
  return <section className="result-card simple-result" aria-live="polite">
    <div className="result-head">
      <div className={`result-icon ${riskClass}`}><ShieldAlert size={20}/></div>
      <div className="result-title">
        <strong>Check complete</strong>
        <small>{result.mode === "demo" ? "Simulated demo result" : result.mode === "hybrid" ? "Local heuristics + Google Web Risk lookup" : "Local heuristic analysis"}</small>
      </div>
      <button className="icon-btn" type="button" aria-label="Dismiss result" onClick={onClose}><X size={17}/></button>
    </div>
    <div className="result-score-row">
      <div><div className="eyebrow">Risk score</div><div className="score-num">{result.score}<span>/100</span></div></div>
      <span className={`risk-pill ${riskClass}`}>{result.level} risk</span>
    </div>
    <p className="result-explanation">{result.explanation}</p>
    {result.threat_intelligence && result.threat_intelligence.status !== "not_checked" && <div className={`threat-intel-status ${result.threat_intelligence.status}`}>
      <div><strong>{result.threat_intelligence.provider === "google_web_risk" ? "Google Web Risk" : "Live reputation lookup"}</strong><span>{result.threat_intelligence.status.replaceAll("_", " ")}</span></div>
      <p>{result.threat_intelligence.message}</p>
      {result.threat_intelligence.threat_types.length > 0 && <p>Threat types: {result.threat_intelligence.threat_types.join(", ")}</p>}
    </div>}
    <div className="result-columns">
      <div><h4>Signals found</h4>{result.indicators.length
        ? result.indicators.map((item) => <div className="result-list-item" key={item}><span className="tiny-bullet"/>{item}</div>)
        : <div className="result-list-item"><Check size={13}/>No configured rules matched. This does not guarantee safety.</div>}
      </div>
      <div><h4>What you can do</h4>{result.recommendations.map((item) => <div className="result-list-item" key={item}><Check size={13}/>{item}</div>)}</div>
    </div>
    <div className="result-time"><Clock3 size={13}/>{new Date(result.created_at).toLocaleString()}</div>
  </section>;
}

export default function App() {
  const [result, setResult] = useState<Result | null>(null);
  return <div className="simple-app">
    <header className="simple-header"><Brand/><span className="simple-header-note"><ShieldCheck size={15}/> Heuristic checks, clearly explained</span></header>
    <main className="simple-main">
      <div className="simple-heading">
        <div className="status-tag"><span className="pulse-dot"/> QUICK CHECK</div>
        <h1>Something seems <span className="gradient-text">suspicious?</span></h1>
        <p>Paste a link, email, message, or payment request. We’ll show the warning signs to consider before you act.</p>
      </div>
      <ScanForm onResult={setResult}/>
      {result && <ResultCard result={result} onClose={() => setResult(null)}/>}
      <p className="simple-disclaimer"><LockKeyhole size={14}/> Don’t include passwords, one-time codes, or payment details. A low score is not a guarantee that something is safe.</p>
      <div className="simple-types" aria-label="Supported content types">
        <span><Link2 size={14}/> Links</span>
        <span><Mail size={14}/> Emails</span>
        <span><MessageSquareText size={14}/> Messages</span>
        <span><CreditCard size={14}/> Payment requests</span>
      </div>
    </main>
    <footer className="simple-footer">ScamShield AI <span>Decision support, not a guarantee of safety.</span></footer>
  </div>;
}
