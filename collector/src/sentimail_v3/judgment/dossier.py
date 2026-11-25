"""Fabrique le dossier complet, puis calcule les barrières avant compaction."""

from __future__ import annotations

import json

import asyncpg
import httpx

from sentimail_v3.code.attack_techniques import dossier_view as techniques_dossier_view
from sentimail_v3.code.attack_techniques import registry as techniques_registry
from sentimail_v3.code.knowledge import reference_for_clues
from sentimail_v3.config import Settings
from sentimail_v3.judgment.dossier_view import (
    _bounded, _cited_code_articles, _code_index, _compact_entities,
    _deduplicate_clues, _fit_dossier,
)
from sentimail_v3.judgment.rules import (
    _judgment_rules, _material_impersonation_profile, _material_spam_profile,
)
from sentimail_v3.observation.dossier.hooks.visible_text import readable_text
from sentimail_v3.observation.visible_content import VISIBLE_CONTENT_VERSION


async def _build_dossier(
    pool: asyncpg.Pool[Any],
    investigation_id: str,
    deep_analysis: dict[str, object],
    *,
    client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> dict[str, object]:
    row = await pool.fetchrow(
        """
        SELECT i.id AS investigation_id, i.status AS investigation_status,
               i.mode, i.favorable_points, i.adverse_points, i.neutral_clues,
               i.completed_at, i.summary AS investigation_summary,
               ce.code_name, ce.version AS code_version,
               m.id AS message_id, m.captured_at, m.smtp_peer_ip::text, m.smtp_helo,
               m.smtp_protocol, m.smtp_tls, m.smtp_authenticated,
               m.envelope_from, m.envelope_recipients, m.raw_size_bytes,
               m.headers_size_bytes, m.body_size_bytes, m.line_count,
               m.contains_8bit, m.contains_nul, m.line_ending,
               m.message_id AS internet_message_id, m.subject, m.from_header,
               m.to_header, m.cc_header, m.reply_to_header,
               m.return_path_header, m.header_date_raw, m.header_date,
               m.header_date_parse_error, m.mime_version, m.root_content_type,
               m.root_charset, m.root_transfer_encoding,
               left(coalesce(m.body_text,''),12000) AS body_text,
               left(coalesce(m.body_html,''),400000) AS body_html,
               m.parser_defects, m.facts
        FROM investigations i
        JOIN messages m ON m.id=i.message_id
        JOIN code_editions ce ON ce.id=i.edition_id
        WHERE i.id=$1::uuid
        """,
        investigation_id,
    )
    if row is None:
        raise RuntimeError("investigation not found")
    attachments = await pool.fetch(
        """
        SELECT path, content_type, content_disposition, filename,
               decoded_size_bytes, decoded_sha256, parameters, defects
        FROM mime_parts
        WHERE message_id=$1 AND is_attachment=true
        ORDER BY ordinal LIMIT 50
        """,
        row["message_id"],
    )
    headers = await pool.fetch(
        """
        SELECT name_normalized, left(value_decoded,4000) AS value
        FROM headers
        WHERE message_id=$1 AND name_normalized = ANY($2::text[])
        ORDER BY ordinal LIMIT 100
        """,
        row["message_id"],
        [
            "authentication-results",
            "x-spamd-result",
            "x-spam-status",
            "received",
            "return-path",
            "dkim-signature",
            "list-id",
            "list-unsubscribe",
            "precedence",
            "x-mailer",
            "user-agent",
        ],
    )
    entities = await pool.fetch(
        """
        SELECT e.entity_type, e.role, e.value_normalized, e.attributes,
               en.status AS enrichment_status, en.source AS enrichment_source,
               en.data AS enrichment_data
        FROM entities e
        LEFT JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1
        ORDER BY e.entity_type, e.ordinal LIMIT 250
        """,
        row["message_id"],
    )
    clues = await pool.fetch(
        """
        SELECT id, article_code, clue_code, direction, strength, confidence,
               statement, facts, provenance
        FROM clues WHERE investigation_id=$1::uuid
        ORDER BY strength DESC, id
        """,
        investigation_id,
    )
    articles = await pool.fetch(
        """
        SELECT ca.article_code, ca.title, ca.principle, ca.default_direction,
               ca.default_strength, ca.severity, ca.limitations, ca.parameters
        FROM code_articles ca
        JOIN investigations i ON i.edition_id=ca.edition_id
        WHERE i.id=$1::uuid AND ca.enabled=true
        ORDER BY ca.article_code
        """,
        investigation_id,
    )
    deduplicated_clues = _deduplicate_clues(list(clues))
    message = dict(row)
    message.pop("message_id", None)
    captured_at = message.pop("captured_at", None)
    # Le juge lit ce que le destinataire lit. Sur un mail HTML seul (30 % du
    # courrier), body_text est vide : le 16 septembre 2026, le juge a écrit
    # « avis de renouvellement avec un lien de gestion » sur un faux reçu dont
    # il n'avait vu ni le RIB, ni le montant, ni « annulation sous 14 jours ».
    # Le HTML brut, lui, ne part toujours pas : seul son texte visible.
    raw_facts = message.get("facts")
    try:
        facts = json.loads(raw_facts) if isinstance(raw_facts, str) else dict(raw_facts or {})
    except (ValueError, TypeError):
        facts = {}
    visible = facts.pop("visible_content", None)
    # Le corps n'est envoyé qu'une fois, jamais recopié dans les faits.
    message["facts"] = facts
    if (isinstance(visible, dict) and visible.get("version") == VISIBLE_CONTENT_VERSION
            and isinstance(visible.get("text"), str) and not visible.get("truncated")):
        texte, source = visible["text"], str(visible.get("source") or "visible_content")
        message.pop("body_text", None)
        message.pop("body_html", None)
    else:
        texte, source = readable_text(message.pop("body_text", None), message.pop("body_html", None))
    message["body_text"] = texte[:12000]
    message["favorable_points"] = sum(
        int(value["strength"])
        for value in deduplicated_clues
        if value["direction"] == "favorable"
    )
    message["adverse_points"] = sum(
        int(value["strength"])
        for value in deduplicated_clues
        if value["direction"] == "adverse"
    )
    deep_history = (
        deep_analysis.get("history")
        if isinstance(deep_analysis.get("history"), dict)
        else {}
    )
    authenticated_feedback = (
        deep_history.get("ground_truth_feedback")
        if isinstance(deep_history, dict)
        and isinstance(deep_history.get("ground_truth_feedback"), list)
        else []
    )
    dossier = {
        "schema": "sentinel-verdict-dossier-v3-trial-roles",
        "privacy": {
            "raw_eml_included": False,
            "html_included": False,
            "attachment_content_included": False,
            "text_truncated_at_chars": 12000,
            "text_source": source,
        },
        "attack_technique_registry": techniques_dossier_view(
            await techniques_registry(pool)
        ),
        "code_index": _code_index(list(articles)),
        "message": message,
        "selected_headers": [dict(value) for value in headers],
        "attachment_metadata": [dict(value) for value in attachments],
        "entities": _compact_entities(list(entities), captured_at=captured_at),
        "deep_analysis": _bounded(deep_analysis),
        "authenticated_user_feedback": _bounded(authenticated_feedback[:8]),
        "learned_signals": _bounded(deep_history.get("learned_signals") or []),
        "clues": [_bounded(value) for value in deduplicated_clues],
        "code_articles": _cited_code_articles(list(articles), deduplicated_clues),
    }
    # La connaissance normative éclaire les indices ; elle n'en produit aucun.
    # Sa place dans le dossier le dit, et le prompt le répète : un extrait de
    # RFC explique ce qu'est un alignement, il ne constate jamais qu'il manque.
    if client is not None and settings is not None:
        passages = await reference_for_clues(
            pool,
            [str(clue["clue_code"]) for clue in deduplicated_clues],
            client=client,
            base_url=settings.knowledge_embedding_url,
            model=settings.knowledge_embedding_model,
        )
        if passages:
            dossier["reference_knowledge"] = {
                "nature": "documentation citable",
                "probative_value": "none",
                "warning": (
                    "Ces extraits décrivent le fonctionnement du courrier. Ils "
                    "ne disent rien de ce message, ne créent aucun indice et "
                    "ne lèvent aucune barrière."
                ),
                "passages": passages,
            }
    # Le dossier sort d'ici complet. Les deux profils matériels et toutes les
    # judgment_rules se calculent sur la liste entière des indices ; seule la
    # vue envoyée au modèle est ensuite ajustée (_prepare_for_judgment).
    codes_complets = {
        str(clue["clue_code"])
        for clue in deduplicated_clues
        if isinstance(clue, dict) and clue.get("clue_code")
    }
    dossier["material_spam_profile"] = _material_spam_profile(codes_complets)
    dossier["material_impersonation_profile"] = _material_impersonation_profile(
        deduplicated_clues
    )
    return dossier


def _prepare_for_judgment(
    dossier: dict[str, object], deep: dict[str, object], settings: Settings, *, max_chars: int | None = None
) -> dict[str, object]:
    """Règles sur les indices complets, puis la vue ajustée au modèle.

    Le modèle peut lire une vue tronquée ; la barrière, jamais. L'ajustement
    n'a lieu qu'une fois : rejoué sur un dossier déjà réduit, il remettait
    truncated_for_llm à faux, et la garde du classifieur local ne voyait
    plus aucun dossier tronqué.
    """
    dossier["judgment_rules"] = _judgment_rules(dossier, deep, settings)
    return _fit_dossier(dossier, max_chars=max_chars)


async def _express_dossier(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, object]:
    """Le dossier du jugement express : son schéma, et les indices du message.

    _complete exige que chaque code cité par un jugement se retrouve dans les
    indices du dossier, pour référencer la preuve par son identifiant. Le
    dossier express se limitait à son schéma : chaque verdict express échouait
    sur KeyError('clues'), et le code à usage unique repartait vers l'examen
    complet - livré en retard, exactement ce que la voie rapide devait éviter.
    """
    rows = await pool.fetch(
        """
        SELECT c.id, c.clue_code, c.article_code, c.direction, c.strength,
               c.confidence, c.statement
        FROM clues c
        JOIN investigations i ON i.id=c.investigation_id
        WHERE i.message_id=$1::uuid
        ORDER BY c.strength DESC, c.id
        """,
        message_id,
    )
    return {
        "schema": "sentimail-verdict-express-one-time-code",
        "clues": [dict(row) for row in rows],
    }
