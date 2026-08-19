import pytest
from aegis.reporters.pdf_gen import block_url_fetcher

def test_block_url_fetcher():
    """Weryfikuje, czy WeasyPrint jest zablokowany przed pobieraniem zasobów (LFI/SSRF)."""
    
    # Funkcja powinna zwrócić pusty słownik zasobu zamiast rzucać błąd
    result = block_url_fetcher("http://malicious.com/image.png")
    
    assert isinstance(result, dict)
    assert result['string'] == b''
    assert result['mime_type'] == 'text/plain'