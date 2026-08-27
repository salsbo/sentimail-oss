from __future__ import annotations

import asyncio
import time

from sentimail_v3.observation.dossier.hook import EvidenceHook
from sentimail_v3.observation.dossier.hooks.attachments import AttachmentHook
from sentimail_v3.observation.dossier.hooks.authentication import AuthenticationHook
from sentimail_v3.observation.dossier.hooks.content import ContentHook
from sentimail_v3.observation.dossier.hooks.headers import HeadersHook
from sentimail_v3.observation.dossier.hooks.identity import IdentityHook
from sentimail_v3.observation.dossier.hooks.nature import NatureHook
from sentimail_v3.observation.dossier.hooks.rspamd import RspamdHook
from sentimail_v3.observation.dossier.hooks.structure import StructureHook
from sentimail_v3.observation.dossier.hooks.transport import TransportHook
from sentimail_v3.observation.dossier.hooks.urls import UrlHook
from sentimail_v3.observation.dossier.models import Clue, HookResult, InvestigationContext


def build_hooks() -> list[EvidenceHook]:
    """Source unique et ordonnée du pipeline d'observation."""
    return [
        StructureHook(),
        HeadersHook(),
        IdentityHook(),
        AuthenticationHook(),
        RspamdHook(),
        TransportHook(),
        ContentHook(),
        NatureHook(),
        UrlHook(),
        AttachmentHook(),
    ]


async def _safe_run(hook: EvidenceHook, context: InvestigationContext) -> HookResult:
    started = time.perf_counter()
    try:
        raw_clues, facts = await asyncio.wait_for(
            hook.observe(context), timeout=hook.timeout_seconds
        )
        clues = [clue for clue in raw_clues if isinstance(clue, Clue)]
        return HookResult(
            hook_name=hook.name,
            hook_version=hook.version,
            status="ok",
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            clues=clues,
            facts=facts,
        )
    except Exception as exc:  # noqa: BLE001 - un hook ne casse jamais le SMTP
        return HookResult(
            hook_name=hook.name,
            hook_version=hook.version,
            status="error",
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            error_type=type(exc).__name__,
            error_detail=str(exc)[:500],
        )


async def run_hooks(
    context: InvestigationContext,
    hooks: list[EvidenceHook] | None = None,
) -> list[HookResult]:
    return [await _safe_run(hook, context) for hook in (hooks or build_hooks())]
