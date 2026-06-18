import yaml
from pathlib import Path
from typing import List
from pydantic import ValidationError
import structlog

from aegis.core.models import PayloadConfig


MAX_FILE_SIZE = 1024 * 1024  # 1 MB
MAX_PAYLOADS = 10000

logger = structlog.get_logger(__name__)

def load_payloads(payload_dir: Path) -> List[PayloadConfig]:
    """Bezpieczne ładowanie i walidacja wektorów ataku z plików YAML."""
    if not payload_dir.exists() or not payload_dir.is_dir():
        raise NotADirectoryError(f"The payloads directory does not exist: {payload_dir}")

    payloads: List[PayloadConfig] =[]
    
    # rglob zapewnia rekursywne przeszukiwanie podkatalogów
    for file_path in payload_dir.rglob("*.y*ml"):

        if not file_path.is_file():
            continue
        
        if file_path.stat().st_size > MAX_FILE_SIZE:
            logger.warning("File skipped: Size limit exceeded (1MB)", file=str(file_path))
            continue

        try:
            # Wymuszenie UTF-8 zapobiega błędom dekodowania przy wielojęzycznych payloadach
            with file_path.open("r", encoding="utf-8") as f:
                # Wyłącznie safe_load
                data = yaml.safe_load(f)
                
            if not isinstance(data, list):
                logger.warning("File skipped: A list of payloads was expected at the top level", file=str(file_path))
                continue

            for item in data:
                if len(payloads) > MAX_PAYLOADS:
                    logger.error("The global payload limit has been exceeded. Uploading has been stopped.")
                    return payloads
                try:
                    payload = PayloadConfig(**item)
                    payloads.append(payload)
                except ValidationError as e:
                    logger.error("Pydantic validation error", file=str(file_path), error=e.errors())
                  
        except yaml.YAMLError as e:
            logger.error("YAML syntax error", file=str(file_path), error=str(e))
        except Exception as e:
            logger.error("Unexpected I/O error", file=str(file_path), error=str(e))

    logger.info("The vector database has finished loading", loaded_count=len(payloads))
    return payloads