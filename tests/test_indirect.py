import pytest
from aegis.core.models import PayloadConfig
from aegis.scanners.indirect import IndirectInjectionBuilder

@pytest.fixture
def base_payload():
    return PayloadConfig(id="ipi_01", name="Test", vector="malicious code", expected_regex=".*")

def test_hidden_dom_payload(base_payload):
    payload = IndirectInjectionBuilder.build_hidden_dom_payload(base_payload)
    assert payload.id == "ipi_01_indirect_dom"
    assert "display: none" in payload.vector
    assert "malicious code" in payload.vector
    assert "indirect_injection" in payload.tags

def test_markdown_payload(base_payload):
    payload = IndirectInjectionBuilder.build_markdown_payload(base_payload)
    assert payload.id == "ipi_01_indirect_md"
    assert "![Company Logo]" in payload.vector
    assert "malicious code" in payload.vector