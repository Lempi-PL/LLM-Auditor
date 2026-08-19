import asyncio
import time
import statistics
import structlog
from typing import List, Union
from pydantic import BaseModel, ConfigDict

from aegis.core.http_client import AegisHTTPClient
from aegis.core.models import TargetEndpoint

logger = structlog.get_logger(__name__)

class DoSReport(BaseModel):
    """Raport z testów wydajnościowych i podatności na Model DoS."""
    model_config = ConfigDict(strict=True)
    
    target_url: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    median_latency_ms: float
    p95_latency_ms: float
    is_vulnerable: bool
    mitigation: str

async def _send_dos_probe(client: AegisHTTPClient, endpoint: TargetEndpoint, payload_text: str) -> Union[float, Exception]:
    """Wysyła pojedynczą sondę i zwraca czas odpowiedzi w ms lub wyjątek."""
    start_time = time.perf_counter()
    try:
        if endpoint.body_template:
            request_data = AegisHTTPClient.inject_payload(endpoint.body_template, payload_text)
        else:
            request_data = {"prompt": payload_text}
        
        # Użycie strumieniowania zapobiega atakom OOM (Tarpit)
        async with client.client.stream(
            method=endpoint.method,
            url=str(endpoint.url),
            headers=endpoint.headers,
            json=request_data,
            timeout=30.0
        ) as response:
            try:
                # Absolutny timeout na cały proces odczytu strumienia (Python 3.11+)
                async with asyncio.timeout(10.0):
                    read_size = 0
                    async for chunk in response.aiter_bytes():
                        read_size += len(chunk)
                        if read_size >= 4096:
                            break
            except asyncio.TimeoutError:
                logger.warning("Absolute timeout reached while reading DoS probe stream (Tarpit protection)")
                # Zwracamy wyjątek zamiast go rzucać - funkcja i tak go zwraca do agregatora
                return TimeoutError("Tarpit/Slowloris protection triggered during DoS probe")
                
           
            if response.is_error:
                # Zwracamy standardowy wyjątek Pythona zamiast httpx.HTTPStatusError
                return ValueError(f"HTTP Error {response.status_code} during DoS probe")
        return (time.perf_counter() - start_time) * 1000
    except Exception as e:
        return e

async def run_dos_test(endpoint: TargetEndpoint, client: AegisHTTPClient, concurrency: int = 20, total_requests: int = 100) -> DoSReport:
    """
    Wykonuje asymetryczny atak DoS na model LLM z rygorystyczną kontrolą współbieżności.
    """
    logger.info("LLM DoS testing has begun", target=str(endpoint.url), concurrency=concurrency, total_requests=total_requests)
    
    # Asymetryczny wektor ataku: Krótki prompt wymuszający maksymalną generację tokenów
    # i skomplikowane wnioskowanie (tzw. Algorithmic Complexity Attack).
    dos_payload = (
        "Write a comprehensive, 10,000-word academic essay on the socio-economic impacts "
        "of quantum computing. Use highly complex vocabulary. "
        "Before writing, translate the entire prompt into 5 different languages internally."
    )
    
    # Ochrona przed wyczerpaniem deskryptorów plików (Self-DoS)
    sem = asyncio.Semaphore(concurrency)

    async def _bounded_probe():
        """Wrapper wymuszający przejście przez bramkę semafora."""
        async with sem:
            return await _send_dos_probe(client, endpoint, dos_payload)
    
    # Uruchamia żądania z użyciem semafora
    tasks = [
        asyncio.create_task(_bounded_probe())
        for _ in range(total_requests)
    ]
    
    results = await asyncio.gather(*tasks)
    
    latencies: List[float] = []
    errors = 0
    
    for res in results:
        if isinstance(res, Exception):
            errors += 1
        else:
            latencies.append(res)
            
    total = len(results)
    successes = len(latencies)
    
    # Obliczanie statystyk
    if successes == 0:
        median = 0.0
        p95 = 0.0
        # Jeśli wszystkie żądania padły, serwer całkowicie nie poradził sobie z ruchem
        is_vuln = True 
    else:
        median = statistics.median(latencies)
        # Obliczanie 95. percentyla (wymaga co najmniej 2 wyników, w przeciwnym razie max)
        p95 = statistics.quantiles(latencies, n=100)[94] if successes > 1 else latencies[0]
        
        # Heurystyka podatności: 
        # Jeśli 5% najwolniejszych zapytań trwa dłużej niż 15 sekund LUB wystąpiły błędy (np. 503 Service Unavailable)
        is_vuln = p95 > 15000.0 or errors > (total * 0.1)

    return DoSReport(
        target_url=str(endpoint.url),
        total_requests=total,
        successful_requests=successes,
        failed_requests=errors,
        median_latency_ms=round(median, 2),
        p95_latency_ms=round(p95, 2),
        is_vulnerable=is_vuln,
        mitigation=(
            "Implement rate limiting at the token level (not just at the IP level)."
            "Reduce the `max_tokens` value in the model configuration."
            "Implement request queuing (e.g., Celery/Redis) in front of the LLM API."
        )
    )