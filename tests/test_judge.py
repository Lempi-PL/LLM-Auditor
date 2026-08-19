import pytest
from aegis.evaluator.judge import LLMJudge

def test_llm_judge_ssrf_protection():
    """Weryfikuje, czy LLM Judge blokuje próby połączenia z zewnętrznymi hostami."""
    
    # Dozwolony host lokalny nie powinien rzucać błędu
    judge = LLMJudge(host="http://localhost:11434")
    assert judge.host == "http://localhost:11434"
    
    # Niedozwolony host zewnętrzny musi rzucić ValueError
    with pytest.raises(ValueError) as exc:
        LLMJudge(host="http://malicious.com:11434")
    
    assert "not allowed" in str(exc.value).lower() or "locally" in str(exc.value).lower()