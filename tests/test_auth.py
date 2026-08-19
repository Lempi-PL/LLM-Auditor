import pytest
from unittest.mock import AsyncMock, MagicMock
from aegis.scanners.auth import JWTAnalyzer
from aegis.core.models import TargetEndpoint

@pytest.mark.asyncio
async def test_jwt_bypass_uses_stream_to_prevent_oom():
    mock_client = MagicMock()
    endpoint = TargetEndpoint(url="http://test.com/api/health", method="GET", headers={})
    
    mock_baseline_resp = MagicMock()
    mock_baseline_resp.status_code = 401
    mock_forged_resp = MagicMock()
    mock_forged_resp.status_code = 200
    
    ctx1 = AsyncMock()
    ctx1.__aenter__.return_value = mock_baseline_resp
    ctx2 = AsyncMock()
    ctx2.__aenter__.return_value = mock_forged_resp
    
    mock_client.stream = MagicMock(side_effect=[ctx1, ctx2])
    
    result = await JWTAnalyzer.verify_auth_bypass(mock_client, endpoint, "forged.jwt.token", {})
    
    assert result is True
    assert mock_client.stream.call_count == 2
    # Upewnij się, że request() nie zostało wywołane (ochrona przed OOM/Tarpit)
    mock_client.request.assert_not_called()