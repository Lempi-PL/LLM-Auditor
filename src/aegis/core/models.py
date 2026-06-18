from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl, ConfigDict

class PayloadConfig(BaseModel):
    """Reprezentacja pojedynczego wektora ataku z pliku YAML."""
    model_config = ConfigDict(strict=True, frozen=True)
    
    id: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., max_length=100)
    vector: str = Field(..., min_length=1, description="Malicious payload(Prompt Injection)")
    expected_regex: str = Field(..., description="A regular expression that verifies the success of an attack")
    tags: List[str] = Field(default_factory=list)

class TargetEndpoint(BaseModel):
    """Konfiguracja celu audytu."""
    model_config = ConfigDict(strict=True, frozen=True)
    
    url: HttpUrl
    method: str = Field(default="POST", pattern="^(GET|POST)$")
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: Optional[Dict[str, Any]] = Field(default=None, description="Request JSON structure template")
    allow_internal: bool = Field(default=False, exclude=True)
    resolved_ip: Optional[str] = Field(default=None, exclude=True)

    
class ScanResult(BaseModel):
    """Wynik pojedynczego testu."""
    model_config = ConfigDict(strict=True)
    
    payload_id: str
    target_url: str
    is_vulnerable: bool
    status: str = "SECURE"
    response_time_ms: float = Field(..., ge=0.0)
    matched_evidence: Optional[str] = None