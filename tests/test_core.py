import pytest
from pydantic import ValidationError
from aegis.core.models import PayloadConfig, TargetEndpoint

def test_payload_config_strict_validation():
    """Weryfikuje, czy Pydantic blokuje nieprawidłowe identyfikatory i typy."""
    # Prawidłowy payload
    valid = PayloadConfig(
        id="test_payload_01",
        name="Test",
        vector="Ignore all",
        expected_regex=".*"
    )
    assert valid.id == "test_payload_01"

    # Błędny ID (Path Traversal attempt)
    with pytest.raises(ValidationError) as exc:
        PayloadConfig(
            id="../etc/passwd",
            name="Test",
            vector="Ignore all",
            expected_regex=".*"
        )
    assert "String should match pattern" in str(exc.value)

    # Błędny typ (Type Confusion)
    with pytest.raises(ValidationError):
        PayloadConfig(
            id="test_02",
            name="Test",
            vector=1337,  # Oczekiwano stringa
            expected_regex=".*"
        )

def test_target_endpoint_url_parsing():
    """Weryfikuje poprawne parsowanie i normalizację URL."""
    endpoint = TargetEndpoint(url="https://api.example.com/v1/chat")
    assert str(endpoint.url) == "https://api.example.com/v1/chat"
    
    with pytest.raises(ValidationError):
        TargetEndpoint(url="ftp://invalid-scheme.com")