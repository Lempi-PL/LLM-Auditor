import os
import copy
import json
import httpx
import socket
import asyncio
import logging
import argparse
import structlog
import ipaddress

from enum import Enum
from pathlib import Path
from urllib.parse import urlparse
from pydantic import TypeAdapter, HttpUrl, ValidationError
from typing import List, Optional
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

from aegis.core.models import TargetEndpoint, ScanResult, PayloadConfig
from aegis.core.loader import load_payloads
from aegis.core.http_client import AegisHTTPClient, AuthRevokedError
from aegis.core.browser import AegisBrowser, BrowserFatalError
from aegis.scanners.nis2_headers import scan_security_headers
from aegis.scanners.heuristic import evaluate_vulnerability
from aegis.scanners.indirect import IndirectInjectionBuilder
from aegis.scanners.auth import JWTAnalyzer
from aegis.scanners.dos import run_dos_test
from aegis.evasion.mutator import PayloadMutator
from aegis.evaluator.judge import LLMJudge
from aegis.reporters.pdf_gen import NIS2ReportGenerator


structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.dict_tracebacks,
        structlog.processors.JSONRenderer() # Wymusza JSON, neutralizuje \n
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
logger = structlog.get_logger(__name__)
console = Console()

class EventType(Enum):
    LLM_START = "LLM_START"
    LLM_END = "LLM_END"
    TASK_COMPLETE = "TASK_COMPLETE"

@dataclass
class ScanEvent:
    type: EventType

class AuditStats:
    def __init__(self, total_tasks: int):
        self.total_tasks = total_tasks
        self.processed_tasks = 0
        self.llm_processed = 0
        self.llm_active = 0
        self._lock = asyncio.Lock()

    async def mark_llm_start(self):
        async with self._lock:
            self.llm_active += 1

    async def mark_llm_end(self):
        async with self._lock:
            self.llm_active -= 1
            self.llm_processed += 1

    async def mark_task_complete(self):
        async with self._lock:
            self.processed_tasks += 1

# --- UI Worker (Konsument) ---
async def ui_worker(queue: asyncio.Queue, progress: Progress, task_id: int, stats: AuditStats):
    """Nasłuchuje zdarzeń i aktualizuje UI."""
    while True:
        event: ScanEvent = await queue.get()
        
        if event.type == EventType.LLM_START: await stats.mark_llm_start()
        elif event.type == EventType.LLM_END: await stats.mark_llm_end()
        elif event.type == EventType.TASK_COMPLETE: await stats.mark_task_complete()
        
        async with stats._lock:
            processed = stats.processed_tasks
            llm_done = stats.llm_processed
            llm_act = stats.llm_active
            pending = stats.total_tasks - processed
            
        desc = (f"[cyan]Tasks: {processed}/{stats.total_tasks} "
                f"(In the queue: {pending}) | "
                f"LLM: {llm_done} (Active: {llm_act})")
        
        progress.update(task_id, advance=1 if event.type == EventType.TASK_COMPLETE else 0, description=desc)
        queue.task_done()

async def scan_payload(
    payload: PayloadConfig,
    endpoint: TargetEndpoint,
    judge_semaphore: asyncio.Semaphore,
    mode: str,
    event_queue: asyncio.Queue,
    client: Optional[AegisHTTPClient] = None,
    browser: Optional[AegisBrowser] = None,
    browser_selectors: dict = None,
    llm_judge: Optional[LLMJudge] = None
) -> ScanResult:
    """Wykonuje pojedynczy skan z ewaluacją warstwową."""
    try:
        # KROK 1: Wstrzyknięcie 
        if mode == "api":
            result = await client.send_payload(endpoint, payload)
        else:
            result = await browser.execute_payload(
                url=str(endpoint.url),
                payload=payload,
                input_selector=browser_selectors["input"],
                submit_selector=browser_selectors["submit"],
                output_selector=browser_selectors["output"]
            )
            
        # KROK 2: Ewaluacja Warstwa 1 
        is_vuln = False
        evidence = None
        status = result.status  # Zachowuje status z warstwy transportowej (np. ERROR)
    
        if result.matched_evidence and status != "ERROR":
            is_vuln, evidence = await evaluate_vulnerability(payload, result.matched_evidence)
            
            # KROK 3: Ewaluacja Warstwa 2 (AI Judge Fallback)
            if not is_vuln and llm_judge and status != "ERROR":
                await event_queue.put(ScanEvent(EventType.LLM_START))
                try: 
                    async with judge_semaphore:
                        judge_res = await llm_judge.evaluate(payload.vector, result.matched_evidence)
                        is_vuln = judge_res.is_vulnerable
                        if is_vuln:
                            evidence = f"[AI JUDGE]: {judge_res.reason}"
                        elif "timeout" in judge_res.reason.lower() or "failure" in judge_res.reason.lower():
                            status = "ERROR"
                            evidence = f"[AI JUDGE ERROR]: {judge_res.reason}"
                finally: 
                    await event_queue.put(ScanEvent(EventType.LLM_END))
                    
        if is_vuln:
            status = "VULNERABLE"

        result.is_vulnerable = is_vuln
        result.status = status
        result.matched_evidence = evidence if (is_vuln or status == "ERROR") else None
        return result
    
    except (AuthRevokedError, BrowserFatalError):
        # Jawna propagacja błędów krytycznych infrastruktury do TaskGroup
        raise
        
    except (httpx.RequestError, httpx.HTTPStatusError, PlaywrightError) as e:
        # Przechwytuje WYŁĄCZNIE znane błędy operacyjne.
        # Błędy programistyczne (KeyError, TypeError) wywołają Fail-Fast w TaskGroup.
        logger.warning("Scan operation error (Network/Browser)", payload_id=payload.id, error=str(e))
        return ScanResult(
            payload_id=payload.id, 
            is_vulnerable=False,
            status="ERROR", 
            matched_evidence=f"Operational Error: {str(e)}",
            target_url=str(endpoint.url),
            response_time_ms=0.0
        )
    
    except Exception as e:
        logger.error("Unexpected internal scanner error", payload_id=payload.id, error=str(e))
        return ScanResult(
            payload_id=payload.id, 
            is_vulnerable=False,
            status="ERROR", 
            matched_evidence=f"Internal Scanner Error: {str(e)}",
            target_url=str(endpoint.url),
            response_time_ms=0.0
        )
    finally:
        await event_queue.put(ScanEvent(EventType.TASK_COMPLETE))

async def payload_worker(
    queue: asyncio.Queue, 
    endpoint: TargetEndpoint, 
    mode: str, 
    event_queue: asyncio.Queue, 
    results: list, 
    judge_semaphore: asyncio.Semaphore, 
    client=None, 
    browser_selectors=None, 
    llm_judge=None
    ):
    """Worker konsumujący payloady. W trybie browser zarządza własną instancją Chromium (Shared-Nothing)."""
    browser = None
    if mode == "browser":
        browser = AegisBrowser(headless=True)
        # Przekazanie hosta i zweryfikowanego IP do przeglądarki
        # W Pydantic V2, endpoint.url.host zwraca domenę (np. "example.com")
        await browser.start(
            target_host=endpoint.url.host,
            resolved_ip=endpoint.resolved_ip
        )

    try:
        while True:
            try:
                payload = queue.get_nowait()
            except asyncio.QueueEmpty:
                break 
                
            result = await scan_payload(
                payload=payload,
                endpoint=endpoint,
                judge_semaphore=judge_semaphore,
                mode=mode,
                event_queue=event_queue,
                client=client,
                browser=browser,
                browser_selectors=browser_selectors,
                llm_judge=llm_judge
            )
            results.append(result)
    finally:
        # Gwarantowane czyszczenie zasobów workera po zakończeniu lub anulowaniu (Cancel)
        if browser:
            await browser.stop()

def expand_payloads(base_payloads: List[PayloadConfig]) -> List[PayloadConfig]:
    """Mnoży bazowe wektory o techniki Evasion i Indirect Injection."""
    expanded = []
    mutator = PayloadMutator()
    
    for p in base_payloads:
        mutated_variants = mutator.generate_all_mutations(p)
        expanded.extend(mutated_variants)
        expanded.extend(IndirectInjectionBuilder.generate_all(p))
        
    unique_payloads = {p.id: p for p in expanded}
    return list(unique_payloads.values())


async def run_audit(args: argparse.Namespace):
    """Główny orkiestrator audytu."""
    safe_target = escape(args.target)
    console.print(Panel.fit(f"[bold cyan]Aegis-LLM Enterprise DAST[/bold cyan]\nTARGET: {safe_target}", border_style="cyan"))
   
   # Wczesna walidacja URL przed jakimikolwiek operacjami sieciowymi
    try:
        TypeAdapter(HttpUrl).validate_python(args.target)
    except ValidationError as e:
        logger.critical("Invalid URL format for the audit target.", error=e.errors())
        console.print("[bold red]CRITICAL ERROR:[/bold red] The URL provided is invalid (the http:// or https:// scheme is required).")
        return
   
   # Ładowanie nagłówków ze zmiennych środowiskowych (Ochrona przed wyciekiem sekretów w CLI)
    custom_headers = {}
   # 1. Wygodny skrót dla Bearer Token 
    bearer_token = os.environ.get("AEGIS_BEARER_TOKEN")
    if bearer_token:
        custom_headers["Authorization"] = f"Bearer {bearer_token}"

    # 2. Wygodny skrót dla API Key 
    api_key = os.environ.get("AEGIS_API_KEY")
    if api_key:
        custom_headers["x-api-key"] = api_key

    # 3. Surowe nagłówki dla nietypowych API i omijania WAF
    raw_headers = os.environ.get("AEGIS_RAW_HEADERS_JSON")
    if raw_headers:
        try:
            custom_headers.update(json.loads(raw_headers))
        except json.JSONDecodeError:
            logger.error("AEGIS_RAW_HEADERS_JSON parsing error")

    # Ładowanie szablonu API (jeśli przekazano)
    body_template = {"prompt": "<<PAYLOAD>>"}
    if args.api_template:
        template_path = Path(args.api_template)
        if template_path.exists():
            if template_path.stat().st_size > 1024 * 1024:
                logger.error(f"The template file exceeds the 1MB limit: {template_path}")
                return
            try:
                with template_path.open("r", encoding="utf-8") as f:
                    body_template = json.load(f)
                console.print(f"[dim]A custom API template has been loaded from: {template_path.name}[/dim]")
            except json.JSONDecodeError as e:
                logger.error("Error parsing the API template file. It must be valid JSON.", error=str(e))
                return
        else:
            logger.error(f"The API template file does not exist: {template_path}")
            return
    # 2. Rozwiązywanie DNS
    parsed_url = urlparse(args.target)
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    resolved_ip = None

    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        
        for info in addr_info:
            ip = info[4][0]
            ip_obj = ipaddress.ip_address(ip)
            if getattr(ip_obj, 'ipv4_mapped', None):
                ip_obj = ip_obj.ipv4_mapped
                
            is_internal = (ip_obj.is_private or ip_obj.is_loopback or 
                           ip_obj.is_link_local or ip_obj.is_reserved or 
                           ip_obj.is_unspecified or ip_obj.is_multicast)
            
            if is_internal and not args.allow_internal_target:
                continue
            resolved_ip = ip
            break
            
        if not resolved_ip:
            logger.critical("SSRF Protection: No allowed IP address for the target.", target=hostname)
            return
            
    except socket.gaierror:
        logger.critical("The target host cannot be resolved.", target=hostname)
        return

    # 3. Bezpieczna inicjalizacja obiektu z twardym IP
    from pydantic import ValidationError

    try:
        endpoint = TargetEndpoint(
            url=args.target, 
            headers=custom_headers, 
            body_template=body_template,
            allow_internal=args.allow_internal_target,
            resolved_ip=resolved_ip
        )
    except ValidationError as e:
        logger.critical("The URL format for the audit target is invalid.", error=e.errors())
        console.print("[bold red]CRITICAL ERROR:[/bold red] The URL provided is invalid (the http:// or https:// scheme is required).")
        return
    
    base_payloads = load_payloads(Path(args.payloads))
    if not base_payloads:
        logger.error("No payloads loaded. Audit aborted.")
        return

    payloads = expand_payloads(base_payloads)
    console.print(f"[dim]Expanded {len(base_payloads)} basis vectors to {len(payloads)} options (Evasion & Indirect).[/dim]")

    llm_judge = LLMJudge(model_name=args.ai_model, host=args.judge_host) if args.use_ai_judge else None
    if llm_judge:
        console.print("[bold purple]LLM-as-a-Judge has been activated[/bold purple]")

    # jwt-token skaner
    jwt_token = os.environ.get("AEGIS_JWT_TOKEN")
    if jwt_token:
        console.print("\n[yellow]Analysis of the JWT token (Algorithm Confusion)...[/yellow]")
        forged = JWTAnalyzer.create_none_algorithm_token(jwt_token)
        if forged:
            try:
                async with AegisHTTPClient(
                    verify_ssl=not args.insecure, 
                    allow_internal=args.allow_internal_target,
                    target_host=endpoint.url.host,
                    resolved_ip=endpoint.resolved_ip
                ) as safe_client:
                    is_bypassed = await JWTAnalyzer.verify_auth_bypass(
                        client=safe_client.client,
                        endpoint=endpoint,
                        forged_token=forged,
                        original_headers=custom_headers
                    )
                    
                    if is_bypassed:
                        console.print(f"[bold red]VULNERABLE:[/bold red] The server accepted the 'none' token and bypassed authentication (Algorithm Confusion).")
                    else:
                        console.print(f"[green]SECURE:[/green] The server rejected the 'none' token or the endpoint is public.")
            except Exception as e:
                console.print(f"[yellow]ERROR:[/yellow] The token could not be verified online: {e}") 

    # Inicjalizacja kolejki Producer-Consumer
    payload_queue = asyncio.Queue()
    for p in payloads:
        payload_queue.put_nowait(p)

    stats = AuditStats(total_tasks=len(payloads))
    event_queue = asyncio.Queue()
    judge_semaphore = asyncio.Semaphore(1)

    scan_results: List[ScanResult] = []
    nis2_report = None
    dos_report = None

    # --- GŁÓWNA PĘTLA AUDYTU ---
    async with AegisHTTPClient(
        verify_ssl=not args.insecure, 
        allow_internal=args.allow_internal_target,
        target_host=endpoint.url.host,
        resolved_ip=endpoint.resolved_ip
    ) as client:
        console.print("\n[yellow]Scanning NIS2 Baseline...[/yellow]")
        nis2_report = await scan_security_headers(endpoint, client.client)
        
        if args.run_dos:
            console.print("\n[yellow]Performing asymmetric DoS attacks...[/yellow]")
            dos_report = await run_dos_test(endpoint, client, concurrency=20)

        console.print(f"\n[yellow]Payload injection (Tryb: {args.mode.upper()})...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=len(payloads))
            worker_task = asyncio.create_task(ui_worker(event_queue, progress, task_id, stats))
            
            progress.update(
                task_id, 
                description=f"[cyan]Tasks: 0/{len(payloads)} (In the queue: {len(payloads)}) | LLM: 0 (Aktywne: 0)"
            )
            
            critical_failure = False
            try:
                if args.mode == "api":
                    async with asyncio.TaskGroup() as tg:
                        for _ in range(args.concurrency):
                            tg.create_task(payload_worker(
                                payload_queue, endpoint, "api", event_queue, scan_results, 
                                judge_semaphore, client=client, llm_judge=llm_judge
                            ))
                            
                elif args.mode == "browser":
                    browser_concurrency = min(args.concurrency, 3)
                    browser_selectors = {
                        "input": args.browser_input,
                        "submit": args.browser_submit,
                        "output": args.browser_output
                    }
                    async with asyncio.TaskGroup() as tg:
                        for _ in range(browser_concurrency):
                            tg.create_task(payload_worker(
                                payload_queue, endpoint, "browser", event_queue, scan_results, 
                                judge_semaphore, browser_selectors=browser_selectors, llm_judge=llm_judge
                            ))
                            
            except* (AuthRevokedError, BrowserFatalError) as eg:
                critical_error = eg.exceptions[0]
                console.print(f"\n[bold red]CRITICAL INFRASTRUCTURE/AUTHORIZATION ERROR:[/bold red] {str(critical_error)}")
                console.print("[yellow]The audit was interrupted. TaskGroup automatically canceled the remaining tasks.[/yellow]")
                critical_failure = True
            
            if not critical_failure:
                await event_queue.join()

            worker_task.cancel()
            try:
                await worker_task
            except asyncio.CancelledError:
                pass

            # Zakończenie funkcji po bezpiecznym zamknięciu kolejki i workera
            if critical_failure:
                return


    # --- RAPORTOWANIE KONSOLOWE ---
    console.print("\n[bold green]Summary of Prompt Injection:[/bold green]")
    pi_table = Table(show_header=True, header_style="bold magenta")
    pi_table.add_column("Payload ID")
    pi_table.add_column("Status", justify="center")
    pi_table.add_column("Time (ms)", justify="right")
    
    vuln_count = 0
    error_count = 0
    
    for res in scan_results:
        if getattr(res, "status", "SECURE") == "ERROR":
            error_count += 1
            pi_table.add_row(res.payload_id, "[bold yellow]ERROR[/bold yellow]", f"{res.response_time_ms:.1f}")
        elif res.is_vulnerable:
            vuln_count += 1
            pi_table.add_row(res.payload_id, "[bold red]VULNERABLE[/bold red]", f"{res.response_time_ms:.1f}")
        else:
            pi_table.add_row(res.payload_id, "[green]SECURE[/green]", f"{res.response_time_ms:.1f}")
            
    console.print(pi_table)
    console.print(f"The following vulnerabilities have been detected: [bold red]{vuln_count}[/bold red] / {len(payloads)}")
    console.print(f"Infrastructure errors: [bold yellow]{error_count}[/bold yellow] / {len(payloads)}\n")

    if dos_report:
        console.print("[bold green]LLM DoS Summary:[/bold green]")
        status = "[bold red]VULNERABLE[/bold red]" if dos_report.is_vulnerable else "[green]SECURE[/green]"
        console.print(f"Status: {status} | P95 Latency: {dos_report.p95_latency_ms}ms | ERRORS: {dos_report.failed_requests}/{dos_report.total_requests}\n")

    # --- GENEROWANIE RAPORTÓW (JSON + PDF) ---
    # Rozwiązanie ścieżki bazowej zapobiega ominięciu przez symlinki
    base_report_dir = (Path.cwd() / "reports").resolve()
    base_report_dir.mkdir(parents=True, exist_ok=True)
    
    # Bezpieczne rozwiązanie ścieżki
    requested_path = Path(args.output).resolve()
    
    # Weryfikacja Path Traversal
    if not requested_path.is_relative_to(base_report_dir):
        logger.critical("A path traversal attempt has been detected!", requested_path=str(requested_path))
        console.print("[bold red]ERROR:[/bold red] Reports can only be saved in the 'reports/' directory.")
        return

    # Atomowe tworzenie plików z bezpiecznymi uprawnieniami (Ochrona TOCTOU)
    def secure_create_file(path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_CREAT (tworzy), O_WRONLY (tylko zapis), O_TRUNC (nadpisuje) z maską 0600
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.close(fd)

    output_path = requested_path
    secure_create_file(output_path) # Zastępuje .touch() i .chmod()

    report_data = {
        "target": args.target,
        "nis2_baseline": nis2_report.model_dump() if nis2_report else None,
        "dos_report": dos_report.model_dump() if dos_report else None,
        "prompt_injection_results": [r.model_dump() for r in scan_results]
    }
    
    # Asynchroniczny zapis zapobiegający blokowaniu pętli zdarzeń
    def secure_write_json(path, data):
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    await asyncio.to_thread(secure_write_json, output_path, report_data)
    console.print(f"[bold cyan]The JSON report has been saved to:[/bold cyan] {escape(str(output_path.resolve()))}")

    try:
        pdf_generator = NIS2ReportGenerator(template_dir=Path("templates"))
        pdf_path = output_path.with_suffix('.pdf')
        secure_create_file(pdf_path)
        await asyncio.to_thread(pdf_generator.generate_pdf, args.target, scan_results, pdf_path)
        console.print(f"[bold cyan]The PDF report has been saved to:[/bold cyan] {pdf_path.resolve()}")
    except Exception as e:
        logger.error("The PDF could not be generated", error=str(e))
    finally:
        # Zapobieganie wyciekom zasobów i procesom Zombie
        from aegis.scanners.heuristic import shutdown_process_pool
        shutdown_process_pool()


def main():
    parser = argparse.ArgumentParser(description="Aegis-LLM: Enterprise DAST dla AI")
    
    parser.add_argument("-t", "--target", required=True, help="The URL of the target API or webpage")
    parser.add_argument("-p", "--payloads", default="payloads", help="Directory containing YAML files")
    parser.add_argument("-o", "--output", default="reports/aegis_report.json", help="JSON output file (a PDF will be generated alongside it)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Limit on concurrent connections")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disables SSL/TLS certificate verification")
    
    parser.add_argument("--mode", choices=["api", "browser"], default="api", help="Injection mode (HTTP API or Playwright)")
    parser.add_argument("--browser-input", default="textarea", help="CSS selector for a text field (browser mode only)")
    parser.add_argument("--browser-submit", default="button[type='submit']", help="CSS selector for the submit button (browser mode only)")
    parser.add_argument("--browser-output", default=".chat-response", help="LLM response CSS selector (browser mode only)")
    parser.add_argument("--api-template", help="Path to the JSON file containing the query template (use <<PAYLOAD>> as a placeholder)")
    parser.add_argument("--allow-internal-target", action="store_true", help="Zezwala na skanowanie adresów prywatnych/lokalnych (np. localhost, 10.x.x.x)")
    
    parser.add_argument("--run-dos", action="store_true", help="Perform asymmetric LLM DoS tests")
    parser.add_argument("--use-ai-judge", action="store_true", help="Use the local Ollam model to analyze logs")
    parser.add_argument("--judge-host", default="http://host.containers.internal:11434", help="Ollama API URL")
    parser.add_argument("--ai-model", default="mistral-nemo:12b", help="Model name for AI Judge (requires a working Ollam)")

    args = parser.parse_args()
    # Ochrona przed Self-DoS (OOM)
    if args.concurrency < 1 or args.concurrency > 100:
        parser.error("The value of --concurrency must be between 1 and 100.")
    asyncio.run(run_audit(args))

if __name__ == "__main__":
    main()