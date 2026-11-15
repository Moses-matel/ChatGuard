from typing import Literal
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

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


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    sha256: str = Field(pattern=HEX64_REGEX)
    file_type: Literal["apk", "pdf", "office", "archive", "unknown"] = Field(
        validation_alias=AliasChoices("file_type", "fileType")
    )
    package_name: str | None = Field(
        default=None, validation_alias=AliasChoices("package_name", "packageName")
    )
    cert_sha256: str | None = Field(
        default=None,
        pattern=HEX64_REGEX,
        validation_alias=AliasChoices("cert_sha256", "certSha256"),
    )
    shown_verdict: Literal["AMAN", "MENCURIGAKAN", "BERBAHAYA"] = Field(
        validation_alias=AliasChoices("shown_verdict", "shownVerdict")
    )
    user_note: str | None = Field(
        default=None,
        max_length=500,
        validation_alias=AliasChoices("user_note", "userNote"),
    )

    @field_validator("file_type", mode="before")
    @classmethod
    def normalize_file_type(cls, v: object) -> object:
        if isinstance(v, str):
            return v.lower()
        return v

    @field_validator("sha256", "cert_sha256", mode="after")
    @classmethod
    def normalize_hex(cls, v: str | None) -> str | None:
        if v is not None:
            return v.lower()
        return v


class ReportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["recorded"] = "recorded"

