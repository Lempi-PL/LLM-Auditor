import re
import httpx
import structlog
from pydantic import BaseModel, ConfigDict
from typing import Optional

from aegis.core.models import TargetEndpoint

logger = structlog.get_logger(__name__)

class HeaderCompliance(BaseModel):
    """Model reprezentujący status pojedynczego nagłówka."""
    model_config = ConfigDict(strict=True)
    
    present: bool
    value: Optional[str] = None
    is_compliant: bool
    mitigation: str

class NIS2BaselineReport(BaseModel):
    """Raport zgodności z podstawową higieną cyberbezpieczeństwa (NIS2 Art. 21)."""
    model_config = ConfigDict(strict=True)
    
    target_url: str
    strict_transport_security: HeaderCompliance
    content_security_policy: HeaderCompliance
    x_content_type_options: HeaderCompliance

async def scan_security_headers(endpoint: TargetEndpoint, client: httpx.AsyncClient) -> NIS2BaselineReport:
    """
    Wykonuje zoptymalizowane zapytanie w celu pobrania i analizy nagłówków bezpieczeństwa.
    """
    url_str = str(endpoint.url)
    logger.info("The NIS2 Baseline scan has begun", target=url_str)
    
    try:
        response = await client.head(url_str)
        # Fallback dla WAF/Load Balancerów blokujących HEAD
        if response.status_code in (403, 405, 501):
            logger.debug("HEAD method rejected, retrying with GET", target=url_str)
            # Użycie stream zapobiega pobieraniu ciała odpowiedzi (Ochrona przed OOM)
            async with client.stream("GET", url_str) as stream_response:
                stream_response.raise_for_status()
                headers = stream_response.headers
        else:
            response.raise_for_status()
            headers = response.headers
    except httpx.HTTPError as e:
        logger.error("Network error while scanning headers", error=str(e))
        # Zwraca pusty raport z flagami błędu, zamiast crashować skaner
        headers = httpx.Headers()


    # Analiza HSTS (Strict-Transport-Security)
    hsts_val = headers.get("strict-transport-security", "").lower()
    hsts_compliant = False
    if hsts_val:
        match = re.search(r"max-age=(\d+)", hsts_val)
        if match:
            age = int(match.group(1))
            # Wymóg NIS2/OWASP: Minimum 1 rok oraz includeSubDomains
            if age >= 31536000 and "includesubdomains" in hsts_val:
                hsts_compliant = True
    
    # Analiza CSP (Content-Security-Policy)
    csp_val = headers.get("content-security-policy")
    # Przynajmniej dyrektywa default-src lub frame-ancestors
    csp_compliant = bool(csp_val and ("default-src" in csp_val.lower() or "frame-ancestors" in csp_val.lower()))
    
    # Analiza X-Content-Type-Options
    xcto_val = headers.get("x-content-type-options")
    xcto_compliant = bool(xcto_val and xcto_val.lower() == "nosniff")

    return NIS2BaselineReport(
        target_url=url_str,
        strict_transport_security=HeaderCompliance(
            present=bool(hsts_val),
            value=hsts_val,
            is_compliant=hsts_compliant,
            mitigation="The absence of HSTS enables SSL stripping (MITM) attacks. Configure the header with a max-age value of at least 31,536,000."
        ),
        content_security_policy=HeaderCompliance(
            present=bool(csp_val),
            value=csp_val,
            is_compliant=csp_compliant,
            mitigation="The absence of CSP makes it easier to carry out XSS and Indirect Prompt Injection attacks. Define strict origins (default-src 'self')."
        ),
        x_content_type_options=HeaderCompliance(
            present=bool(xcto_val),
            value=xcto_val,
            is_compliant=xcto_compliant,
            mitigation="The absence of 'nosniff' allows the browser to guess MIME types, which can lead to MIME confusion attacks."
        )
    )