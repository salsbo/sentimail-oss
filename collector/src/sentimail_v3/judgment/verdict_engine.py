"""Point d’entrée du worker de jugement ; traitement dans judgment.workflow."""
from __future__ import annotations

import asyncio
from sentimail_v3.judgment import workflow as _workflow

from sentimail_v3.judgment.claims import resume_interrupted_runs
from sentimail_v3.judgment.prompt import PROMPT_VERSION
from sentimail_v3.judgment.events import _log
import asyncpg
import httpx
from sentimail_v3.config import load_settings
from sentimail_v3.conversation.conversation import ConversationStore
from sentimail_v3.crypto import load_key
from sentimail_v3.execution.delivery import retry_one_release
from sentimail_v3.execution.review_guard import reconcile_one_review_hold
from sentimail_v3.identity import instance_identity
from sentimail_v3.judgment.verdict_retry import MAX_ATTEMPTS, TRANSIENT_RETRY_DELAYS
from sentimail_v3.supervision.health import pulse
from sentimail_v3.judgment.workflow import _process_one

def __getattr__(name):
    return getattr(_workflow, name)

async def main() -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=4)
    await resume_interrupted_runs(pool)
    encryption_key = load_key(settings.raw_eml_key_file)
    identite = await instance_identity(pool, settings)
    conversations = ConversationStore(
        pool,
        identite.action_address,
        identite.assistant_sender,
        settings.render_sandbox_url,
        identite.action_aliases,
        encryption_key,
        settings=settings,
    )
    _log(
        "worker.started",
        component="verdict",
        model=settings.deepseek_verdict_model,
        prompt_version=PROMPT_VERSION,
        interval_seconds=settings.verdict_interval_seconds,
        max_attempts=MAX_ATTEMPTS,
        transient_retry_delays_seconds=[
            int(delay.total_seconds()) for delay in TRANSIENT_RETRY_DELAYS
        ],
        not_before=settings.verdict_not_before,
        decision_mode=settings.decision_mode,
        auto_delivery_confidence=settings.auto_delivery_confidence,
        decision_authority="final_verdict",
        post_judgment_veto=False,
        concurrency=settings.verdict_concurrency,
    )

    async def worker(worker_id: int, client: httpx.AsyncClient) -> None:
        while True:
            pulse("verdict")
            worked = False
            if worker_id == 0:
                try:
                    worked = await reconcile_one_review_hold(
                        pool, settings, conversations
                    )
                    worked = await retry_one_release(pool, settings) or worked
                except Exception as exc:  # noqa: BLE001 - nouvelle tentative bornee
                    _log("delivery.retry.error", error=type(exc).__name__)
                    worked = True
            worked = await _process_one(pool, client, settings, conversations) or worked
            pulse("verdict")
            if not worked:
                await asyncio.sleep(settings.verdict_interval_seconds)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.deepseek_timeout_seconds)
    ) as client:
        await asyncio.gather(
            *(worker(worker_id, client) for worker_id in range(settings.verdict_concurrency))
        )

if __name__ == "__main__":
    asyncio.run(main())
