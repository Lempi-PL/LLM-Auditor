import asyncio
import structlog
from urllib.parse import urlparse
from typing import Optional
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from aegis.core.models import PayloadConfig, ScanResult

logger = structlog.get_logger(__name__)

class BrowserFatalError(Exception):
    """Wyjątek krytyczny oznaczający permanentną awarię silnika przeglądarki."""
    pass

class BrowserRetriableError(Exception):
    """Wyjątek niekrytyczny oznaczający przejściową awarię (np. timeout uruchamiania)."""
    pass

class AegisBrowser:
    """Silnik przeglądarki przypisany na wyłączność do pojedynczego workera (Shared-Nothing)."""
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.playwright = None
        self.browser: Optional[Browser] = None
        
        self.target_host = None
        self.resolved_ip = None

        self._consecutive_failures = 0
        self.MAX_FAILURES = 3
        self.LAUNCH_TIMEOUT = 5.0


    async def start(self, target_host: str = None, resolved_ip: str = None):
        """Inicjalizacja zasobów workera."""
        self.target_host = target_host
        self.resolved_ip = resolved_ip
        
        self.playwright = await async_playwright().start()
        
        args = [
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--incognito",
        ]
        
        # Wymusza na Chromium użycie zweryfikowanego IP
        if self.target_host and self.resolved_ip:
            args.append(f"--host-resolver-rules=MAP {self.target_host} {self.resolved_ip}")

        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=args
        )


    async def stop(self):
        """Bezpieczne czyszczenie zasobów workera i procesów Zombie."""
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
        if self.playwright:
            try:
                await self.playwright.stop()
            except Exception:
                pass

    
    async def _heal_process(self):
        """Self-Healing z poprawną re-inicjalizacją całego stosu Playwright."""
        if self._consecutive_failures >= self.MAX_FAILURES:
            raise BrowserFatalError(f"Worker browser permanently dead after {self.MAX_FAILURES} failures.")
            
        logger.warning("The worker detected a dead Chromium process. Restarting the instance....", attempt=self._consecutive_failures + 1)
        
        try:
            await self.stop()
        except Exception:
            pass
            
        try:
            # Ponowna inicjalizacja niskopoziomowego sterownika Node.js
            self.playwright = await async_playwright().start()
            
            args=[
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-software-rasterizer",
                    "--incognito",
            ]
            
            # Odtwarzanie reguły DNS podczas restartu awaryjnego
            if self.target_host and self.resolved_ip:
                args.append(f"--host-resolver-rules=MAP {self.target_host} {self.resolved_ip}")

            self.browser = await asyncio.wait_for(
                self.playwright.chromium.launch(
                    headless=self.headless,
                    args=args
                ),
                timeout=self.LAUNCH_TIMEOUT
            )
            self._consecutive_failures = 0
        except Exception as e:
            self._consecutive_failures += 1
            raise BrowserRetriableError(f"Worker browser launch failed: {e}") from e

    async def execute_payload(
        self, 
        url: str, 
        payload: PayloadConfig, 
        input_selector: str, 
        submit_selector: str, 
        output_selector: str,
        timeout_ms: int = 10000
    ) -> ScanResult:
        
        start_time = asyncio.get_event_loop().time()
        response_text = ""
        status = "SECURE"
        context = None
        
        try:
            # Weryfikacja stanu wewnątrz bloku try, aby przechwycić BrowserRetriableError
            if not self.browser or not self.browser.is_connected():
                await self._heal_process()
                
            context = await self.browser.new_context()
            page = await context.new_page()
            
            # Interceptor blokujący SSRF z subrequestów
            async def block_internal_routing(route):
                request_url = route.request.url
                parsed_url = urlparse(request_url)
                hostname = parsed_url.hostname
                
                # BIAŁA LISTA (Allowlist) zamiast czarnej listy
                if parsed_url.scheme not in ("http", "https"):
                    if request_url != "about:blank": 
                        logger.warning("A dangerous URI scheme has been blocked.", url=request_url)
                        return await route.abort()
                
                if not hostname:
                    logger.warning("A request with an undefined host has been blocked.", url=request_url)
                    return await route.abort()
                    
                if hostname == self.target_host:
                    return await route.continue_()
                    
                safe_cdns = {
                    "cdn.jsdelivr.net", 
                    "cdnjs.cloudflare.com", 
                    "fonts.googleapis.com", 
                    "fonts.gstatic.com"
                }
                if hostname in safe_cdns:
                    return await route.continue_()
                    
                logger.warning("The request to the third-party domain has been blocked.", url=request_url)
                return await route.abort()
        
            await page.route("**/*", block_internal_routing)
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            await page.fill(input_selector, payload.vector, timeout=timeout_ms)
            await page.click(submit_selector, timeout=timeout_ms)
            
            await page.wait_for_selector(output_selector, state="visible", timeout=timeout_ms)
            
            # Zsynchronizowany timeout i ochrona przed wyciekiem interwałów w V8
            js_polling_code = """
            (args) => {
                return new Promise((resolve) => {
                    const { selector, timeout } = args;
                    let prevLen = -1;
                    let stable = 0;
                    
                    const interval = setInterval(() => {
                        const el = document.querySelector(selector);
                        
                        // Protection against Stale Element Reference / DOM Mutation
                        // We only abort the current iteration, allowing another attempt in 300 ms.
                        if (!el) return; 
                        
                        const currLen = el.innerText.length;
                        if (currLen > 0 && currLen === prevLen) {
                            stable++;
                            if (stable >= 3) {
                                clearInterval(interval);
                                resolve(el.innerText);
                            }
                        } else {
                            stable = 0;
                            prevLen = currLen;
                        }
                    }, 300);
                    
                    // Dynamic fallback synchronized with the Python layer
                    setTimeout(() => {
                        clearInterval(interval);
                        const finalEl = document.querySelector(selector);
                        resolve(finalEl ? finalEl.innerText : "");
                    }, timeout);
                });
            }
            """
            # Przekazanie dynamicznych argumentów do V8
            response_text = await page.evaluate(
                js_polling_code, 
                {"selector": output_selector, "timeout": timeout_ms}
            )
            
            # Sukces wykonawczy resetuje licznik awarii (Ochrona przed Poison Pill)
            self._consecutive_failures = 0
            
        except BrowserFatalError:
            raise 
            
        except BrowserRetriableError as e:
            logger.warning("The vector was omitted due to a temporary browser malfunction", payload_id=payload.id)
            response_text = f"Retriable Error: {str(e)}"
            status = "ERROR"
            
        except Exception as e:
            logger.error("Playwright interaction error", url=url, payload_id=payload.id, error=str(e))
            response_text = f"Playwright Error: {str(e)}"
            status = "ERROR"
            
            # Rejestracja awarii wykonawczej (Execution Phase Crash)
            if not self.browser or not self.browser.is_connected():
                self._consecutive_failures += 1
                
        finally:
            if context:
                try:
                    # Ochrona przed Exception Masking
                    await context.close()
                except Exception as cleanup_error:
                    logger.debug("A context closure error was ignored (the process is likely dead)", error=str(cleanup_error))
            
        elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        
        return ScanResult(
            payload_id=payload.id,
            target_url=url,
            is_vulnerable=False,
            status=status,
            response_time_ms=elapsed_ms,
            matched_evidence=response_text if response_text else None
        )