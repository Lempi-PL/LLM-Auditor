import pytest
import jwt
from unittest.mock import AsyncMock, MagicMock
import httpx
from aegis.scanners.auth import JWTAnalyzer
from aegis.scanners.nis2_headers import scan_security_headers
from aegis.core.models import TargetEndpoint

@pytest.fixture
def sample_jwt():
    payload = {"sub": "1234567890", "roles": ["user"]}
    secret = "super-secret-key-256-bit-minimum-length-padding-for-security"
    return jwt.encode(payload, secret, algorithm="HS256")

def test_jwt_privilege_escalation(sample_jwt):
    """Weryfikuje naprawiony błąd unhashable type i poprawną eskalację."""
    escalated_token = JWTAnalyzer.elevate_privileges(sample_jwt, target_role="admin")
    assert escalated_token is not None
    
    decoded = JWTAnalyzer.decode_unsafe(escalated_token)
    # Sprawdza, czy lista ról została poprawnie nadpisana
    assert decoded["roles"] == ["admin"]

@pytest.mark.asyncio
async def test_nis2_scanner_compliant():
    """Weryfikuje rygorystyczną logikę HSTS i fallback do bezpiecznego strumieniowania (stream)."""
    endpoint = TargetEndpoint(url="https://secure.example.com")
    
    # Mockowanie klienta HTTP
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    # Symulacja odrzucenia HEAD (405)
    head_response = MagicMock(status_code=405)
    mock_client.head.return_value = head_response
    
    # Symulacja sukcesu GET (200) przez bezpieczny stream()
    stream_response = MagicMock()
    stream_response.status_code = 200
    stream_response.headers = httpx.Headers({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff"
    })
    
    # Konfiguracja asynchronicznego menedżera kontekstu dla client.stream()
    mock_client.stream.return_value.__aenter__.return_value = stream_response

    report = await scan_security_headers(endpoint, mock_client)
    
    # Asercje weryfikujące logikę biznesową
    mock_client.head.assert_called_once()
    mock_client.stream.assert_called_once() # Fallback przez stream() zadziałał
    assert report.strict_transport_security.is_compliant is True
    assert report.content_security_policy.is_compliant is True