import httpx
import httpcore
import socket
import ipaddress
import asyncio
import structlog
import time
from typing import Optional, Any

from aegis.core.models import TargetEndpoint, PayloadConfig, ScanResult

logger = structlog.get_logger(__name__)

class AuthRevokedError(Exception):
    """Wyjątek krytyczny przerywający globalną pętlę audytu (Circuit Breaker)."""
    pass


class SSRFProtectedNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    Niestandardowy backend sieciowy zapobiegający atakom DNS Rebinding.
    Wykorzystuje pre-rezolwowane IP dla hosta docelowego (Single Source of Truth),
    a dla pozostałych żądań wykonuje bezpieczną rezolucję w locie.
    """
    def __init__(self, original_backend: httpcore.AsyncNetworkBackend, allow_internal: bool, target_host: Optional[str] = None, resolved_ip: Optional[str] = None):
        self.original_backend = original_backend
        self.allow_internal = allow_internal
        self.target_host = target_host
        self.resolved_ip = resolved_ip

    async def connect_tcp(self, host: str, port: int, timeout: Optional[float] = None, local_address: Optional[str] = None, **kwargs):
        valid_ip = None
        
        # Ochrona TOCTOU. Jeśli żądanie dotyczy celu audytu, używamy zweryfikowanego IP.
        if self.target_host and host == self.target_host and self.resolved_ip:
            valid_ip = self.resolved_ip
        else:
            # Bezpieczna rezolucja dynamiczna dla innych domen (np. subrequesty)
            loop = asyncio.get_running_loop()
            try:
                addr_info = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror:
                raise ValueError(f"SSRF Protection: Unable to resolve the host {host}.")
                
            for info in addr_info:
                ip = info[4][0]
                ip_obj = ipaddress.ip_address(ip)

                if getattr(ip_obj, 'ipv4_mapped', None):
                    ip_obj = ip_obj.ipv4_mapped
                    
                is_internal = (ip_obj.is_private or ip_obj.is_loopback or 
                               ip_obj.is_link_local or ip_obj.is_reserved or
                               ip_obj.is_unspecified or ip_obj.is_multicast)
                
                if is_internal and not self.allow_internal:
                    continue
                    
                valid_ip = ip
                break
                
        if not valid_ip:
            raise ValueError(f"SSRF Protection: No allowed IP addresses for {host} (DNS Rebinding blocked).")
            
        # Łączenie z fizycznym, zweryfikowanym adresem IP, ignorując hosta
        return await self.original_backend.connect_tcp(valid_ip, port, timeout=timeout, local_address=local_address, **kwargs)


    async def connect_tls(self, stream, hostname: str, timeout: Optional[float] = None, **kwargs):
        return await self.original_backend.connect_tls(stream, hostname, timeout=timeout, **kwargs)


    async def connect_unix_socket(self, path: str, timeout: Optional[float] = None, **kwargs):
        if not self.allow_internal:
            raise ValueError("SSRF Protection: Connections via Unix sockets are blocked.")
        return await self.original_backend.connect_unix_socket(path, timeout=timeout, **kwargs)


class AegisHTTPClient:
    """Asynchroniczny klient HTTP zoptymalizowany pod kątem audytów DAST."""
    def __init__(self, verify_ssl: bool = True, timeout_sec: float = 10.0, allow_internal: bool = False, target_host: Optional[str] = None, resolved_ip: Optional[str] = None):
        if not verify_ssl:
            logger.warning("SSL/TLS verification is DISABLED. Use only for local testing or via a proxy (e.g., ZAP/Burp).")
        
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
        timeout = httpx.Timeout(timeout_sec)
        base_transport = httpx.AsyncHTTPTransport(verify=verify_ssl, retries=0)
        
        # Bezpieczne wstrzyknięcie niestandardowego backendu sieciowego (Monkeypatching instancji)
        if hasattr(base_transport, '_pool') and hasattr(base_transport._pool, '_network_backend'):
            safe_backend = SSRFProtectedNetworkBackend(
                original_backend=base_transport._pool._network_backend,
                allow_internal=allow_internal,
                target_host=target_host,     # <--- Przekazanie hosta
                resolved_ip=resolved_ip      # <--- Przekazanie IP
            )
            base_transport._pool._network_backend = safe_backend
        else:
            # Fail-Closed z poprzedniej iteracji
            error_msg = "Critical security error: Unable to inject DNS rebinding protection. The httpx version is incompatible."
            logger.critical(error_msg)
            raise RuntimeError(error_msg)

        self.client = httpx.AsyncClient(
            transport=base_transport,
            limits=limits,
            timeout=timeout,
            follow_redirects=False
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    

    @staticmethod
    def inject_payload(data: Any, payload_vector: str, depth: int = 0) -> Any:
        """Rekursywne przeszukiwanie struktury z twardym limitem głębokości (Ochrona przed DoS)."""
        if depth > 20:
            # 20 poziomów zagnieżdżenia 
            raise ValueError("The JSON nesting limit (Max 20) has been exceeded. Injection has been stopped.")
            
        if isinstance(data, dict):
            # Rekurencyjne wywołanie metody statycznej
            return {k: AegisHTTPClient.inject_payload(v, payload_vector, depth + 1) for k, v in data.items()}
        elif isinstance(data, list):
            # Rekurencyjne wywołanie metody statycznej
            return [AegisHTTPClient.inject_payload(item, payload_vector, depth + 1) for item in data]
        elif isinstance(data, str) and "<<PAYLOAD>>" in data:
            return data.replace("<<PAYLOAD>>", payload_vector)
        return data
    
    
    async def send_payload(self, endpoint: TargetEndpoint, payload: PayloadConfig) -> ScanResult:
        """Wysyła pojedynczy wektor ataku z obsługą dynamicznych szablonów."""
        start_time = time.perf_counter()
        response_text = ""
        status = "SECURE"
            
        try:
            if endpoint.body_template:
                request_data = AegisHTTPClient.inject_payload(endpoint.body_template, payload.vector)
            else:
                request_data = {"prompt": payload.vector}
                
            # NAPRAWA: Użycie strumieniowania z limitem odczytu (Ochrona przed OOM/Tarpit)
            async with self.client.stream(
                method=endpoint.method,
                url=str(endpoint.url),
                headers=endpoint.headers,
                json=request_data
            ) as response:
                response.raise_for_status()
                # Odczytuje maksymalnie 500KB danych
                raw_bytes = await response.aread(500_000)
                response_text = raw_bytes.decode("utf-8", errors="ignore")
            
        except ValueError as e:
            logger.error("Payload construction error (Recursion)", url=str(endpoint.url), error=str(e))
            response_text = f"Payload Error: {str(e)}"
            status = "ERROR"
            
        except httpx.HTTPStatusError as e:
            # KRYTYCZNE: Circuit Breaker dla błędów autoryzacji
            if e.response.status_code in (401, 403):
                logger.critical("Authorization denied (401/403). Global audit interruption.", url=str(endpoint.url))
                raise AuthRevokedError(f"Authentication revoked or invalid: HTTP {e.response.status_code}")
                
            logger.error("HTTP status error", url=str(endpoint.url), status_code=e.response.status_code)
            response_text = e.response.text 
            
        except httpx.RequestError as e:
            logger.error("Network error", url=str(endpoint.url), error=str(e))
            response_text = f"Network Error: {str(e)}"
            status = "ERROR"
            
        except Exception as e:
            logger.error("Unexpected HTTP error", url=str(endpoint.url), error=str(e))
            response_text = f"Unexpected Error: {str(e)}"
            status = "ERROR"
            
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return ScanResult(
            payload_id=payload.id,
            target_url=str(endpoint.url),
            is_vulnerable=False, 
            status=status,
            response_time_ms=elapsed_ms,
            matched_evidence=response_text
        )