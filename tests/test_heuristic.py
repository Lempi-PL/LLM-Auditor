import pytest
from aegis.core.models import PayloadConfig
from aegis.scanners.heuristic import _extract_clean_text_sync
from aegis.scanners.heuristic import evaluate_vulnerability

@pytest.mark.asyncio
async def test_json_key_extraction():
    """Weryfikuje naprawiony błąd OWASP LLM01 (False Negative w kluczach JSON)."""
    payload = PayloadConfig(
        id="json_leak",
        name="JSON Leak",
        vector="test",
        expected_regex="SYSTEM_COMPROMISED"
    )
    
    # Złośliwy ciąg znajduje się w KLUCZU, a nie w wartości
    raw_response = '{"SYSTEM_COMPROMISED": "safe_value"}'
    
    is_vuln, evidence = await evaluate_vulnerability(payload, raw_response)
    
    assert is_vuln is True
    assert evidence == "SYSTEM_COMPROMISED"

def test_extract_clean_text_sync_xml():
    """Pokrywa linie 58-63: Parsowanie XML."""
    xml_data = "<?xml version='1.0'?><root>secret_payload_here</root>"
    result = _extract_clean_text_sync(xml_data)
    assert "secret_payload_here" in result

def test_extract_clean_text_sync_html():
    """Pokrywa linie 66-73: Parsowanie HTML."""
    html_data = "<html><body><div class='chat'>hidden_xss_payload</div></body></html>"
    result = _extract_clean_text_sync(html_data)
    assert "hidden_xss_payload" in result

@pytest.mark.asyncio
async def test_evaluate_vulnerability_truncation():
    """Pokrywa linie 122-124: Obcinanie gigantycznych odpowiedzi (Ochrona przed OOM/ReDoS)."""
    payload = PayloadConfig(id="test", name="test", vector="v", expected_regex="VULN")
    
    # Tworzymy odpowiedź przekraczającą MAX_RESPONSE_LENGTH (500_000)
    huge_response = "VULN" + ("A" * 500_001)
    
    is_vuln, evidence = await evaluate_vulnerability(payload, huge_response)
    
    assert is_vuln is True
    # Dowód (evidence) również powinien zostać obcięty przez silnik RE2 do max 500 znaków
    assert len(evidence) <= 500