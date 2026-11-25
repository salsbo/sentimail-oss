from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any

import asyncpg

from sentimail_v3.crypto import protect, reveal
from sentimail_v3.execution.delivery_state import DEFERRED, DELIVERED, move
from sentimail_v3.observation.dossier import run_hooks
from sentimail_v3.observation.dossier.models import HookResult, InvestigationContext
from sentimail_v3.observation.entities import extract_entities
from sentimail_v3.observation.parser import ParsedMessage, parse_message
from sentimail_v3.observation.visible_content import build_visible_content
from sentimail_v3.postgres_values import pg_json, pg_jsonsafe, pg_text
from sentimail_v3.supervision.core_rollout import generation_for_capture


@dataclass(frozen=True)
class CaptureResult:
    message_id: str
    delivery_status: str
    inserted: bool


def _json(value: object) -> str:
    return pg_json(value)


def _raw_facts(raw: bytes) -> dict[str, object]:
    separator = b"\r\n\r\n"
    boundary = raw.find(separator)
    if boundary < 0:
        separator = b"\n\n"
        boundary = raw.find(separator)
    headers_size = len(raw) if boundary < 0 else boundary + len(separator)
    lines = raw.splitlines()
    if b"\r\n" in raw and raw.replace(b"\r\n", b"").find(b"\n") < 0:
        line_ending = "crlf"
    elif b"\r\n" not in raw and b"\n" in raw:
        line_ending = "lf"
    else:
        line_ending = "mixed_or_none"
    return {
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size_bytes": len(raw),
        "headers_size_bytes": headers_size,
        "body_size_bytes": max(0, len(raw) - headers_size),
        "line_count": len(lines),
        "max_line_length": max((len(line) for line in lines), default=0),
        "contains_8bit": any(byte > 127 for byte in raw),
        "contains_nul": b"\x00" in raw,
        "line_ending": line_ending,
    }


def ingest_key(raw: bytes, sender: str, recipients: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(raw)
    digest.update(b"\x00")
    digest.update(sender.encode("utf-8", errors="surrogatepass"))
    for recipient in sorted(recipients, key=str.casefold):
        digest.update(b"\x00")
        digest.update(recipient.encode("utf-8", errors="surrogatepass"))
    return digest.hexdigest()


class Store:
    def __init__(
        self, pool: asyncpg.Pool[Any], encryption_key: bytes | None = None
    ) -> None:
        self.pool = pool
        self.encryption_key = encryption_key

    async def capture(
        self,
        raw: bytes,
        sender: str,
        recipients: list[str],
        smtp: dict[str, object],
    ) -> CaptureResult:
        parsed = parse_message(raw)
        raw_values = _raw_facts(raw)
        # L'empreinte et les mesures portent sur le message original ; seul son
        # stockage est chiffré, pour que l'analyse reste identique.
        stored_raw, encryption = protect(raw, self.encryption_key)
        entities = extract_entities(raw, parsed, sender, recipients)
        hook_results = await run_hooks(
            InvestigationContext(
                raw=raw,
                parsed=parsed,
                envelope_from=sender,
                recipients=recipients,
            )
        )
        key = ingest_key(raw, sender, recipients)
        # Les vues SQL ne peuvent pas contenir NUL. L'EML, les empreintes et
        # les mesures ci-dessus gardent les octets observés, sans modification.
        message_values = pg_jsonsafe(parsed.message)

        async with self.pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                INSERT INTO messages (
                    ingest_key, smtp_peer_ip, smtp_peer_port, smtp_helo, smtp_protocol,
                    smtp_tls, smtp_authenticated, envelope_from, envelope_recipients,
                    smtp_mail_options, smtp_rcpt_options, raw_eml, raw_eml_encryption,
                    raw_sha256,
                    raw_size_bytes, headers_size_bytes, body_size_bytes, line_count,
                    max_line_length, contains_8bit, contains_nul, line_ending,
                    message_id, subject, from_header, to_header, cc_header,
                    reply_to_header, return_path_header, header_date_raw, header_date,
                    header_date_parse_error, mime_version, root_content_type,
                    root_charset, root_transfer_encoding, body_text, body_html,
                    parser_version, parser_defects, facts, delivery_attempts
                ) VALUES (
                    $1, $2::inet, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11::jsonb,
                    $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
                    $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35,
                    $36, $37, $38, $39, $40::jsonb, $41::jsonb, 1
                )
                ON CONFLICT (ingest_key) DO UPDATE SET
                    delivery_attempts = messages.delivery_attempts + 1,
                    last_delivery_error = NULL
                RETURNING id::text, delivery_status, (xmax = 0) AS inserted
                """,
                key,
                smtp.get("peer_ip"),
                smtp.get("peer_port"),
                pg_text(smtp.get("helo")),
                pg_text(smtp.get("protocol")),
                _json(smtp.get("tls") or {}),
                smtp.get("authenticated"),
                pg_text(sender),
                pg_jsonsafe(recipients),
                pg_jsonsafe(list(smtp.get("mail_options") or [])),
                _json(smtp.get("rcpt_options") or {}),
                stored_raw,
                encryption,
                raw_values["raw_sha256"],
                raw_values["raw_size_bytes"],
                raw_values["headers_size_bytes"],
                raw_values["body_size_bytes"],
                raw_values["line_count"],
                raw_values["max_line_length"],
                raw_values["contains_8bit"],
                raw_values["contains_nul"],
                raw_values["line_ending"],
                *[
                    message_values[key]
                    for key in (
                        "message_id",
                        "subject",
                        "from_header",
                        "to_header",
                        "cc_header",
                        "reply_to_header",
                        "return_path_header",
                        "header_date_raw",
                        "header_date",
                        "header_date_parse_error",
                        "mime_version",
                        "root_content_type",
                        "root_charset",
                        "root_transfer_encoding",
                        "body_text",
                        "body_html",
                        "parser_version",
                    )
                ],
                _json(message_values["parser_defects"]),
                _json({**parsed.facts, "visible_content": build_visible_content(
                    message_values.get("body_text"), message_values.get("body_html")
                )}),
            )
            assert row is not None
            result = CaptureResult(
                message_id=row["id"],
                delivery_status=row["delivery_status"],
                inserted=row["inserted"],
            )
            if result.inserted:
                await self._insert_children(
                    connection, result.message_id, parsed, entities
                )
                await self._insert_investigation(
                    connection, result.message_id, hook_results
                )
                # La génération ne dépend que de la configuration qualifiée,
                # jamais du correspondant. Le savepoint protège la capture
                # durable si la supervision de bascule devient indisponible.
                generation = "legacy"
                try:
                    async with connection.transaction():
                        async with asyncio.timeout(1):
                            generation = await generation_for_capture(connection, result.message_id)
                except Exception as exc:
                    await connection.execute(
                        "INSERT INTO audit_log(actor,action,payload) "
                        "VALUES('capture','core.generation_fallback',$1::jsonb)",
                        _json({"message_id": result.message_id, "error_type": type(exc).__name__}),
                    )
                await connection.execute(
                    "UPDATE messages SET engine_generation=$2,engine_generation_assigned_at=now() "
                    "WHERE id=$1::uuid AND engine_generation_assigned_at IS NULL",
                    result.message_id, generation,
                )
            return result

    async def _insert_children(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        parsed: ParsedMessage,
        entities: list[dict[str, object]],
    ) -> None:
        await connection.executemany(
            """
            INSERT INTO headers (
                message_id, ordinal, name_original, name_normalized, value_raw,
                value_decoded, value_sha256, value_length, is_trace, is_security
            ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            """,
            [(message_id, *pg_jsonsafe(row).values()) for row in parsed.headers],
        )
        await connection.executemany(
            """
            INSERT INTO mime_parts (
                message_id, path, parent_path, ordinal, is_multipart, is_attachment,
                content_type, maintype, subtype, charset, content_transfer_encoding,
                content_disposition, filename, content_id, content_description,
                content_language, content_location, decoded_size_bytes, decoded_sha256,
                text_content, parameters, defects
            ) VALUES (
                $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                $18,$19,$20,$21::jsonb,$22::jsonb
            )
            """,
            [
                (
                    message_id,
                    *list(row.values())[:-2],
                    _json(row["parameters"]),
                    _json(row["defects"]),
                )
                for row in pg_jsonsafe(parsed.parts)
            ],
        )
        await connection.executemany(
            """
            INSERT INTO entities (
                message_id, entity_type, role, ordinal, value_raw,
                value_normalized, attributes
            ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::jsonb)
            """,
            [
                (
                    message_id,
                    row["entity_type"],
                    row["role"],
                    row["ordinal"],
                    row["value_raw"],
                    row["value_normalized"],
                    _json(row["attributes"]),
                )
                for row in pg_jsonsafe(entities)
            ],
        )

    async def reinvestigate(self, message_id: str) -> bool:
        """Rejoue les hooks sur un message conservé et remplace son dossier.

        Les en-têtes, parties MIME et entités sont issus du même EML : ils ne
        changent pas et ne sont pas retouchés. Seule l'observation, qui dépend
        du code des hooks, est refaite. Un verdict accepté interdit ce rejeu.
        Une vue lisible absente peut être ajoutée tant que l'original existe.
        """
        row = await self.pool.fetchrow(
            """
            SELECT raw_eml, envelope_from, envelope_recipients
            FROM messages WHERE id=$1::uuid
            """,
            message_id,
        )
        if row is None or row["raw_eml"] is None:
            return False
        raw = reveal(row["raw_eml"], self.encryption_key)
        if raw is None:
            return False
        parsed = parse_message(raw)
        recipients = list(row["envelope_recipients"])
        hook_results = await run_hooks(
            InvestigationContext(
                raw=raw,
                parsed=parsed,
                envelope_from=str(row["envelope_from"]),
                recipients=recipients,
            )
        )
        async with self.pool.acquire() as connection, connection.transaction():
            # Un rejeu ne ressuscite pas le contenu purgé pendant l'observation
            # et ne remplace jamais une décision déjà acceptée.
            available = await connection.fetchrow(
                "SELECT raw_eml FROM messages WHERE id=$1::uuid FOR UPDATE", message_id
            )
            if available is None or available["raw_eml"] is None:
                return False
            await connection.fetch(
                "SELECT id FROM investigations WHERE message_id=$1::uuid FOR UPDATE", message_id
            )
            if await connection.fetchval(
                """SELECT EXISTS(SELECT 1 FROM verdicts v JOIN investigations i
                   ON i.id=v.investigation_id WHERE i.message_id=$1::uuid AND v.is_binding)""",
                message_id,
            ):
                return False
            await connection.execute(
                """UPDATE messages SET facts=jsonb_set(facts,'{visible_content}',$2::jsonb)
                   WHERE id=$1::uuid AND NOT (facts ? 'visible_content')""",
                message_id,
                _json(build_visible_content(
                    parsed.message.get("body_text"), parsed.message.get("body_html")
                )),
            )
            await connection.execute(
                "DELETE FROM investigations WHERE message_id=$1::uuid", message_id
            )
            await self._insert_investigation(
                connection, message_id, hook_results, create_case=False
            )
            await connection.execute(
                """
                UPDATE delivery_cases dc SET investigation_id=i.id, updated_at=now()
                FROM investigations i
                WHERE i.message_id=$1::uuid AND dc.message_id=$1::uuid
                """,
                message_id,
            )
        return True

    async def _insert_investigation(
        self,
        connection: asyncpg.Connection,
        message_id: str,
        hook_results: list[HookResult],
        *,
        create_case: bool = True,
    ) -> None:
        edition = await connection.fetchrow(
            """
            SELECT id, code_name, version
            FROM code_editions
            WHERE code_name='Code Sentinel' AND status='active'
            """
        )
        if edition is None:
            raise RuntimeError("no active Code Sentinel edition")

        favorable = sum(
            clue.strength
            for result in hook_results
            for clue in result.clues
            if clue.direction == "favorable"
        )
        adverse = sum(
            clue.strength
            for result in hook_results
            for clue in result.clues
            if clue.direction == "adverse"
        )
        neutral = sum(
            clue.direction == "neutral"
            for result in hook_results
            for clue in result.clues
        )
        status = (
            "partial" if any(r.status == "error" for r in hook_results) else "complete"
        )
        investigation_id = await connection.fetchval(
            """
            INSERT INTO investigations (
                message_id, edition_id, mode, status, favorable_points,
                adverse_points, neutral_clues, completed_at, summary
            ) VALUES ($1::uuid,$2,'observation',$3,$4,$5,$6,now(),$7::jsonb)
            RETURNING id::text
            """,
            message_id,
            edition["id"],
            status,
            favorable,
            adverse,
            neutral,
            _json(
                {
                    "hook_count": len(hook_results),
                    "hook_errors": [
                        r.hook_name for r in hook_results if r.status == "error"
                    ],
                    "binding": False,
                }
            ),
        )
        articles = {
            row["article_code"]: row
            for row in await connection.fetch(
                """
                SELECT id, article_code, title, principle, default_direction,
                       default_strength, severity, limitations, parameters
                FROM code_articles WHERE edition_id=$1 AND enabled=true
                """,
                edition["id"],
            )
        }
        favorable_ids: list[int] = []
        adverse_ids: list[int] = []
        for run_order, result in enumerate(hook_results):
            hook_run_id = await connection.fetchval(
                """
                INSERT INTO hook_runs (
                    investigation_id, hook_name, hook_version, run_order, status,
                    duration_ms, facts, error_type, error_detail
                ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
                RETURNING id
                """,
                investigation_id,
                pg_text(result.hook_name),
                pg_text(result.hook_version),
                run_order,
                pg_text(result.status),
                result.duration_ms,
                _json(result.facts),
                pg_text(result.error_type),
                pg_text(result.error_detail),
            )
            for ordinal, clue in enumerate(result.clues):
                article = articles.get(clue.article_code)
                snapshot = dict(article) if article is not None else {}
                if snapshot.get("id") is not None:
                    snapshot["id"] = str(snapshot["id"])
                clue_id = await connection.fetchval(
                    """
                    INSERT INTO clues (
                        investigation_id, hook_run_id, article_id, article_code,
                        clue_code, direction, strength, confidence, statement,
                        facts, provenance, article_snapshot, ordinal
                    ) VALUES (
                        $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,
                        $12::jsonb,$13
                    ) RETURNING id
                    """,
                    investigation_id,
                    hook_run_id,
                    article["id"] if article is not None else None,
                    pg_text(clue.article_code),
                    pg_text(clue.clue_code),
                    pg_text(clue.direction),
                    clue.strength,
                    clue.confidence,
                    pg_text(clue.statement),
                    _json(clue.facts),
                    _json(clue.provenance),
                    _json(snapshot),
                    ordinal,
                )
                if clue.direction == "favorable":
                    favorable_ids.append(clue_id)
                elif clue.direction == "adverse":
                    adverse_ids.append(clue_id)

        await connection.execute(
            """
            INSERT INTO verdicts (
                investigation_id, classification, source, confidence, rationale,
                evidence_for, evidence_against, is_binding
            ) VALUES ($1::uuid,'undetermined','observation_pipeline',NULL,$2,$3,$4,false)
            """,
            investigation_id,
            "Aucune qualification automatique à ce stade.",
            favorable_ids,
            adverse_ids,
        )
        if create_case:
            await connection.execute(
                """
                INSERT INTO delivery_cases (
                    message_id, investigation_id, assessed_classification, state,
                    original_delivery_allowed, binding, details
                ) VALUES (
                    $1::uuid,$2::uuid,'undetermined','observation_only',true,false,$3::jsonb
                )
                """,
                message_id,
                investigation_id,
                _json(
                    {
                        "policy": "deliver_all_during_observation",
                        "smtp_actions_enabled": False,
                        "review_notice_enabled": False,
                    }
                ),
            )
        await connection.execute(
            """
            INSERT INTO audit_log (actor, action, payload)
            VALUES ('collector','investigation.created',$1::jsonb)
            """,
            _json(
                {
                    "message_id": message_id,
                    "edition": f"{edition['code_name']} {edition['version']}",
                    "status": status,
                    "favorable_points": favorable,
                    "adverse_points": adverse,
                    "binding": False,
                }
            ),
        )

    async def mark_delivered(self, message_id: str) -> None:
        async with self.pool.acquire() as connection, connection.transaction():
            await move(connection, message_id, DELIVERED)
            await connection.execute(
                """
                WITH changed AS (
                    UPDATE delivery_cases
                    SET state='original_delivered', updated_at=now()
                    WHERE message_id=$1::uuid AND state='observation_only'
                    RETURNING id
                )
                INSERT INTO delivery_events (case_id, event_type, details)
                SELECT id, 'original_delivered', '{"binding":false,"mode":"observation"}'::jsonb
                FROM changed
                """,
                message_id,
            )

    async def mark_deferred(self, message_id: str, error: str) -> None:
        await move(self.pool, message_id, DEFERRED, error=pg_text(error[:2000]))
