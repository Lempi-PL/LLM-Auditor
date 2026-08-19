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


@pytest.mark.asyncio
async def test_nis2_scanner_non_compliant():
    """Weryfikuje zachowanie skanera, gdy serwer nie posiada nagłówków bezpieczeństwa."""
    endpoint = TargetEndpoint(url="http://insecure.example.com")
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    # Symulacja odpowiedzi bez nagłówków bezpieczeństwa
    head_response = MagicMock(status_code=200)
    head_response.headers = httpx.Headers({"Server": "nginx"})
    mock_client.head.return_value = head_response

    report = await scan_security_headers(endpoint, mock_client)
    
    assert report.strict_transport_security.is_compliant is False
    assert report.content_security_policy.is_compliant is False
    assert report.x_content_type_options.is_compliant is False

@pytest.mark.asyncio
async def test_nis2_scanner_network_error():
    """Pokrywa linie 46-51: Obsługa błędu sieciowego (httpx.HTTPError)."""
    endpoint = TargetEndpoint(url="https://error.example.com")
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    # Symulacja całkowitego błędu sieci (np. DNS resolution failed)
    mock_client.head.side_effect = httpx.HTTPError("Network failure")
    
    report = await scan_security_headers(endpoint, mock_client)
    
    # Skaner nie powinien crashować, lecz zwrócić pusty, negatywny raport
    assert report.strict_transport_security.present is False
    assert report.content_security_policy.is_compliant is False

# --- DODATKOWE TESTY DLA AUTH.PY ---
def test_decode_unsafe_dos_protection():
    """Pokrywa linie 32-34: Ochrona przed atakiem DoS (zbyt duży token)."""
    huge_token = "A" * 8193  # Przekracza limit 8192 znaków
    assert JWTAnalyzer.decode_unsafe(huge_token) is None

def test_decode_unsafe_invalid_token():
    """Pokrywa linie 39-40: Obsługa nieprawidłowego formatu JWT."""
    assert JWTAnalyzer.decode_unsafe("not.a.valid.jwt") is None

def test_elevate_privileges_custom_role_injection():
    """Pokrywa linie 117-126: Wstrzykiwanie roli, gdy brakuje standardowych kluczy."""
    # Token bez klucza "roles" czy "group"
    payload = {"sub": "123", "name": "John"}

    # Użycie bezpiecznego, długiego klucza do testów (min. 32 bajty dla HS256)
    safe_secret = "super-secret-key-256-bit-minimum-length-padding-for-security"
    token = jwt.encode(payload, safe_secret, algorithm="HS256")
    
    escalated = JWTAnalyzer.elevate_privileges(token, "superadmin")
    decoded = JWTAnalyzer.decode_unsafe(escalated)
    
    # Skaner powinien utworzyć nowy klucz "role"
    assert decoded["role"] == "superadmin"