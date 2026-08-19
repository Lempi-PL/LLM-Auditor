import pytest
import asyncio
import httpx

from aegis.core.http_client import AuthRevokedError
from unittest.mock import AsyncMock, MagicMock
from aegis.core.http_client import AegisHTTPClient
from aegis.core.models import TargetEndpoint, PayloadConfig

@pytest.mark.asyncio
async def test_send_payload_handles_500_and_tarpit():
    client = AegisHTTPClient.__new__(AegisHTTPClient)
    client.client = MagicMock()
    
    mock_response = AsyncMock()
    mock_response.status_code = 500
    mock_response.is_error = True
    
    async def mock_aiter_bytes():
        yield b"Internal Server Error"
        
    mock_response.aiter_bytes = mock_aiter_bytes
    
    mock_stream_ctx = AsyncMock()
    mock_stream_ctx.__aenter__.return_value = mock_response
    client.client.stream.return_value = mock_stream_ctx
    
    endpoint = TargetEndpoint(url="http://test.com", method="POST", headers={})
    payload = PayloadConfig(id="test", name="test", vector="v", expected_regex=".*")
    
    result = await client.send_payload(endpoint, payload)
    
    assert result.status == "ERROR"
    assert "Internal Server Error" in result.matched_evidence


def test_inject_payload_nested_json():
    """Weryfikuje rekurencyjne wstrzykiwanie payloadu do szablonu API."""
    template = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "<<PAYLOAD>>"}
        ]
    }
    
    result = AegisHTTPClient.inject_payload(template, "MALICIOUS_PROMPT")
    
    assert result["messages"][1]["content"] == "MALICIOUS_PROMPT"
    assert result["model"] == "gpt-4" # Reszta struktury nienaruszona

@pytest.mark.asyncio
async def test_send_payload_auth_revoked():
    """Weryfikuje, czy błąd 401 rzuca krytyczny wyjątek AuthRevokedError (Circuit Breaker)."""
    client = AegisHTTPClient.__new__(AegisHTTPClient)
    
    # KRYTYCZNE: Musi być MagicMock, aby stream() nie zwracał korutyny
    client.client = MagicMock()
    
    # Symulacja błędu 401 Unauthorized
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.is_error = True
    
    # Błąd jest rzucany podczas wywołania raise_for_status()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Unauthorized", request=MagicMock(), response=mock_response
    )
    
    # Poprawne mockowanie asynchronicznego menedżera kontekstu
    mock_stream_ctx = AsyncMock()
    mock_stream_ctx.__aenter__.return_value = mock_response
    client.client.stream.return_value = mock_stream_ctx
    
    endpoint = TargetEndpoint(url="http://test.com", method="POST", headers={})
    payload = PayloadConfig(id="test", name="test", vector="v", expected_regex=".*")
    
    with pytest.raises(AuthRevokedError):
        await client.send_payload(endpoint, payload)


def test_inject_payload_list_and_recursion():
    """Pokrywa linie 121-133: Wstrzykiwanie do list i limit zagnieżdżenia."""
    # Test wstrzykiwania do listy
    template_list = ["safe_string", "<<PAYLOAD>>"]
    res = AegisHTTPClient.inject_payload(template_list, "ATTACK")
    assert res[1] == "ATTACK"
    
    # Test limitu rekurencji (Ochrona przed Stack Overflow)
    nested_dict = {}
    current = nested_dict
    for _ in range(25):  # Przekracza limit depth=20
        current["key"] = {}
        current = current["key"]
        
    with pytest.raises(ValueError, match="JSON nesting limit"):
        AegisHTTPClient.inject_payload(nested_dict, "ATTACK")


@pytest.mark.asyncio
async def test_send_payload_success_path():
    """Pokrywa linie 180-197: Prawidłowe wykonanie żądania HTTP."""
    client = AegisHTTPClient.__new__(AegisHTTPClient)
    
    # Musi być MagicMock, aby stream() nie zwracał korutyny
    client.client = MagicMock()
    
    # Symulacja udanej odpowiedzi 200 OK
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.is_error = False
    
    # KRYTYCZNE: Mockowanie asynchronicznego generatora aiter_bytes()
    async def mock_aiter_bytes():
        yield b"LLM_RESPONSE_DATA"
        
    mock_response.aiter_bytes = mock_aiter_bytes
    
    # Poprawne mockowanie asynchronicznego menedżera kontekstu
    mock_stream_ctx = AsyncMock()
    mock_stream_ctx.__aenter__.return_value = mock_response
    client.client.stream.return_value = mock_stream_ctx
    
    endpoint = TargetEndpoint(url="http://test.com", method="POST", headers={})
    payload = PayloadConfig(id="test", name="test", vector="v", expected_regex=".*")
    
    result = await client.send_payload(endpoint, payload)
    
    # Status transportowy to SECURE (ewaluacja podatności dzieje się później)
    assert result.status == "SECURE"
    assert result.matched_evidence == "LLM_RESPONSE_DATA"