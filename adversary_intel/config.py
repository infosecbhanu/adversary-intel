from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Scanning
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    fofa_email: Optional[str] = None
    fofa_api_key: Optional[str] = None

    # Passive DNS / WHOIS
    securitytrails_api_key: Optional[str] = None
    validin_api_key: Optional[str] = None
    domaintools_user: Optional[str] = None
    domaintools_key: Optional[str] = None

    # Threat feeds
    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    # Anomali ThreatStream
    anomali_url: str = "https://api.threatstream.com"
    anomali_username: Optional[str] = None
    anomali_api_key: Optional[str] = None

    # MISP
    misp_url: Optional[str] = None
    misp_key: Optional[str] = None
    misp_verify_ssl: bool = True

    # OpenCTI
    opencti_url: Optional[str] = None
    opencti_token: Optional[str] = None

    # App behaviour
    log_level: str = "INFO"
    rate_limit_delay: float = 1.0
    max_pivot_depth: int = 3
    graph_output_dir: Path = Path("./output/graphs")
    rules_output_dir: Path = Path("./output/rules")

    @field_validator("graph_output_dir", "rules_output_dir", mode="before")
    @classmethod
    def _make_path(cls, v: str | Path) -> Path:
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def available_feeds(self) -> list[str]:
        feeds = ["abusech", "malwarebazaar", "crtsh"]  # always available (no key)
        if self.virustotal_api_key:
            feeds.append("virustotal")
        if self.otx_api_key:
            feeds.append("otx")
        if self.anomali_username and self.anomali_api_key:
            feeds.append("anomali")
        if self.misp_url and self.misp_key:
            feeds.append("misp")
        if self.opencti_url and self.opencti_token:
            feeds.append("opencti")
        return feeds

    def available_scanners(self) -> list[str]:
        scanners = []
        if self.shodan_api_key:
            scanners.append("shodan")
        if self.censys_api_id and self.censys_api_secret:
            scanners.append("censys")
        if self.fofa_email and self.fofa_api_key:
            scanners.append("fofa")
        return scanners


settings = Settings()
