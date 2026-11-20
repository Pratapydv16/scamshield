from detection_engine.engine import analyze


def test_suspicious_url_exposes_signals_and_bounded_score():
    result = analyze("url", "http://192.0.2.1/urgent-verify-your-account")
    assert 0 <= result.risk_score <= 100
    assert result.risk_level in {"low", "elevated", "high"}
    assert {finding.code for finding in result.findings} >= {"unencrypted_transport", "ip_host", "urgency_language"}
    assert result.recommendations
    assert "not proof" in result.explanation


def test_email_header_mismatch_is_reported():
    result = analyze("email", "From: support@example.com\nReply-To: help@different.test\nSubject: Invoice")
    assert "reply_domain_mismatch" in {finding.code for finding in result.findings}


def test_plain_text_is_not_claimed_safe():
    result = analyze("sms", "See you at lunch.")
    assert result.risk_score == 0
    assert "not a guarantee" in result.explanation


def test_invalid_empty_input_is_rejected():
    try:
        analyze("sms", " \n ")
    except ValueError as error:
        assert "empty" in str(error)
    else:
        raise AssertionError("empty input should be rejected")


def test_malformed_url_is_reported_instead_of_crashing():
    result = analyze("url", "http://[invalid")
    assert "malformed_url" in {finding.code for finding in result.findings}


def test_non_http_url_scheme_is_flagged():
    result = analyze("url", "ftp://files.example.test/archive")
    assert "unsupported_scheme" in {finding.code for finding in result.findings}
