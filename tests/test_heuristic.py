import pytest
from aegis.core.models import PayloadConfig
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