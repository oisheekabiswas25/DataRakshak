from app.recognizers.indian_pii_detector import analyze_text, redact_text


def test_detects_pan_format():
    text = "PAN: ABCDE1234F"
    found = analyze_text(text)
    assert any(item["entity_type"] == "IN_PAN" for item in found)


def test_detects_aadhaar_format():
    text = "Aadhaar: 2345 6789 0123"
    found = analyze_text(text)
    assert any(item["entity_type"] == "IN_AADHAAR" for item in found)


def test_redacts_pan():
    redacted = redact_text("PAN: ABCDE1234F")
    assert "ABCDE1234F" not in redacted
    assert "PAN_REDACTED" in redacted
