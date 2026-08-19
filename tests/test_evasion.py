import pytest
import base64
from aegis.core.models import PayloadConfig
from aegis.evasion.mutator import PayloadMutator

@pytest.fixture
def base_payload():
    return PayloadConfig(
        id="base_01",
        name="Base Payload",
        vector="system prompt leak",
        expected_regex=".*"
    )

def test_base64_mutation(base_payload):
    """Weryfikuje poprawność kodowania Base64."""
    mutator = PayloadMutator()
    mutated = mutator.mutate_base64(base_payload)
    
    assert mutated.id == "base_01_b64"
    assert "evasion_base64" in mutated.tags
    
    # Sprawdzenie, czy oryginalny wektor jest zakodowany wewnątrz nowego
    encoded_original = base64.b64encode(b"system prompt leak").decode("utf-8")
    assert encoded_original in mutated.vector
    
    # Weryfikacja niemutowalności (oryginał nie uległ zmianie)
    assert base_payload.vector == "system prompt leak"

def test_homoglyph_mutation(base_payload):
    """Weryfikuje faktyczną translację znaków na cyrylicę."""
    mutator = PayloadMutator()
    mutated = mutator.mutate_homoglyph(base_payload)
    
    # 'a' (U+0061) powinno zostać zamienione na 'а' (U+0430)
    assert "a" in base_payload.vector
    assert "a" not in mutated.vector
    assert "а" in mutated.vector # Cyrylica
    
    # Długość stringa powinna pozostać identyczna
    assert len(mutated.vector) == len(base_payload.vector)

def test_cognitive_bypass(base_payload):
    """Weryfikuje opakowywanie wektora w scenariusz akademicki."""
    mutator = PayloadMutator()
    mutated = mutator.mutate_cognitive_bypass(base_payload)
    
    assert mutated.id == "base_01_cognitive"
    assert "evasion_cognitive" in mutated.tags
    assert "<scenario>" in mutated.vector
    assert base_payload.vector in mutated.vector

def test_generate_all_mutations(base_payload):
    """Weryfikuje, czy generator zwraca wszystkie 4 warianty (oryginał + 3 mutacje)."""
    mutator = PayloadMutator()
    all_payloads = mutator.generate_all_mutations(base_payload)
    
    assert len(all_payloads) == 4
    ids = [p.id for p in all_payloads]
    assert "base_01" in ids
    assert "base_01_b64" in ids
    assert "base_01_homoglyph" in ids
    assert "base_01_cognitive" in ids