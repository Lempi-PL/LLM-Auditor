import os
import re2
import json
import asyncio
import structlog
import multiprocessing
from typing import Tuple, Optional
from bs4 import BeautifulSoup
from defusedxml import ElementTree as ET
from defusedxml.ElementTree import ParseError
from aegis.core.models import PayloadConfig
from pebble import ProcessPool
from concurrent.futures import TimeoutError as PebbleTimeoutError

logger = structlog.get_logger(__name__)

# Limit  tekstu (ochrona przed ReDoS i OOM)
MAX_RESPONSE_LENGTH = 500_000  # 500 KB
# Globalny semafor ograniczający liczbę procesów do ilości rdzeni
MAX_PROCESSES = min(4, max(1, os.cpu_count() or 1))
_process_pool = ProcessPool(
    max_workers=MAX_PROCESSES, 
    context=multiprocessing.get_context("spawn")
)

_pool_semaphore = asyncio.Semaphore(MAX_PROCESSES)

def shutdown_process_pool():
    """Bezpieczne zamykanie puli procesów Pebble."""
    logger.info("Closing the job queue...")
    _process_pool.close()
    _process_pool.join()

    
def _extract_clean_text_sync(raw_response: str) -> str:
    """
    Synchroniczna funkcja CPU-bound.
    Ekstrahuje czysty tekst z odpowiedzi, neutralizując struktury JSON, HTML i XML.
    """
    text_to_analyze = raw_response.strip()

    # 1. Próba parsowania jako JSON
    if text_to_analyze.startswith("{") and text_to_analyze.endswith("}"):
        try:
            parsed_json = json.loads(text_to_analyze)
            extracted = []
            def extract_strings(obj, depth=0):
                if depth > 20:
                    return # Zabezpieczenie przed RecursionError
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        extracted.append(str(k))
                        extract_strings(v, depth + 1)
                elif isinstance(obj, list):
                    for item in obj: 
                        extract_strings(item, depth + 1)
                elif isinstance(obj, str):
                    extracted.append(obj)
                    
            extract_strings(parsed_json)
            return " ".join(extracted)
        except json.JSONDecodeError:
            pass

    # 2. Próba parsowania jako XML
    if text_to_analyze.startswith("<?xml") or text_to_analyze.startswith("<root"):
        try:
            root = ET.fromstring(text_to_analyze)
            return "".join(root.itertext())
        except ParseError:
            pass

     # 3. Próba parsowania jako HTML
    if "<html" in text_to_analyze.lower() or "<body" in text_to_analyze.lower() or "<div" in text_to_analyze.lower():
            try:
            # html.parser rzuci RecursionError przy ataku DoS, chroniąc proces przed Segfaultem.
                soup = BeautifulSoup(text_to_analyze, "html.parser")
                return soup.get_text(separator=" ", strip=True)
            except Exception as e:
                # Fallback w przypadku skrajnie zniekształconego HTML, z którym lxml sobie nie poradzi
                logger.warning("HTML parsing error (potential DoS attack mitigated)", error=str(e))
                pass

    return text_to_analyze


async def _extract_clean_text_safe(raw_response: str, timeout: float = 5.0) -> str:
   
    try:
        async with _pool_semaphore:
            # Pebble natywnie wspiera timeout i ZABIJA proces roboczy po jego upływie
            future = _process_pool.schedule(_extract_clean_text_sync, args=(raw_response,), timeout=timeout)
            # Oczekuje na wynik asynchronicznie, nie blokując pętli zdarzeń
            return await asyncio.wrap_future(future)
    except PebbleTimeoutError:
        logger.warning("HTML parsing timeout (DoS protection - Process terminated).")
        return raw_response
    except Exception as e:
        logger.error("Error in the workflow", error=str(e))
        return raw_response
        

def _regex_search_sync(pattern_str: str, text: str, payload_id: str) -> Optional[str]:
    """Izolacja regexu z użyciem silnika RE2 (Ochrona przed ReDoS)."""
    try:
        # RE2 automatycznie odrzuca wzorce o wykładniczej złożoności czasowej
        pattern = re2.compile(f"(?is){pattern_str}")
        match = pattern.search(text)
        if match:
            evidence = match.group(0)
            return evidence[:497] + "..." if len(evidence) > 500 else evidence
    except re2.error as e:
        logger.error("RE2 expression compilation error (Dangerous pattern rejected)", payload_id=payload_id, error=str(e))
    return None

async def evaluate_vulnerability(payload: PayloadConfig, raw_response: str) -> Tuple[bool, Optional[str]]:
    """
    Ocenia, czy odpowiedź zawiera dowód na udany atak Prompt Injection.
    Zwraca krotkę: (czy_podatny, dopasowany_fragment_dowodowy).
    """
    if not raw_response:
        return False, None

    if len(raw_response) > MAX_RESPONSE_LENGTH:
        logger.warning("The response exceeds the limit, truncated", payload_id=payload.id, length=len(raw_response))
        raw_response = raw_response[:MAX_RESPONSE_LENGTH]

    try:
        clean_text = await _extract_clean_text_safe(raw_response, timeout=5.0)
    except asyncio.TimeoutError:
        # ProcessPoolExecutor pozwala na ubicie procesu roboczego w razie potrzeby
        logger.warning("Response parsing timeout (potential DoS)", payload_id=payload.id)
        return False, None

    evidence = await asyncio.to_thread(_regex_search_sync, payload.expected_regex, clean_text, payload.id)

    if evidence:
        return True, evidence
    return False, None

