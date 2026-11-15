from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

HEX64_REGEX = r"^[0-9a-fA-F]{64}$"


class CheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: str | None = Field(default=None, pattern=HEX64_REGEX)
    urls: list[str] = Field(default_factory=list, max_length=50)
    cert_sha256: str | None = Field(default=None, pattern=HEX64_REGEX)

    @field_validator("sha256", "cert_sha256", mode="after")
    @classmethod
    def normalize_hex(cls, v: str | None) -> str | None:
        if v is not None:
            return v.lower()
        return v


class CheckResponse(BaseModel):
    verdict: Literal["clean", "unknown", "malicious"]
    threat_category: str | None = None
    official_cert_match: bool | None = None
    flagged_urls: list[str] = Field(default_factory=list)
