from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from sentimail_v3.observation.parser import ParsedMessage

Direction = Literal["favorable", "adverse", "neutral"]
RunStatus = Literal["ok", "skip", "error"]


@dataclass(frozen=True)
class InvestigationContext:
    raw: bytes
    parsed: ParsedMessage
    envelope_from: str
    recipients: list[str]


@dataclass(frozen=True)
class Clue:
    article_code: str
    clue_code: str
    direction: Direction
    strength: int
    confidence: float
    statement: str
    facts: dict[str, object] = field(default_factory=dict)
    provenance: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.strength <= 100:
            raise ValueError("strength must be between 0 and 100")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True)
class HookResult:
    hook_name: str
    hook_version: str
    status: RunStatus
    duration_ms: float
    clues: list[Clue] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)
    error_type: str | None = None
    error_detail: str | None = None
