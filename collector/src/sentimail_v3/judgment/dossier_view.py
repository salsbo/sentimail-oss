"""Vue compacte du dossier destinée au juge, sans règle de décision."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg

from sentimail_v3.observation.domain_age import domain_age
from sentimail_v3.postgres_values import pg_jsonsafe

MAX_LLM_DOSSIER_CHARS = 140_000


def _json_default(value: object) -> str:
    if isinstance(value, (datetime, date, UUID, Decimal)):
        return str(value)
    raise TypeError(f"unsupported JSON type: {type(value).__name__}")


def _json(value: object) -> str:
    return json.dumps(
        pg_jsonsafe(value), ensure_ascii=False, separators=(",", ":"), default=_json_default
    )


def _bounded(value: object, *, depth: int = 0) -> object:
    if depth >= 4:
        return "[depth-limited]"
    if isinstance(value, str):
        return value[:1200]
    if isinstance(value, list):
        return [_bounded(item, depth=depth + 1) for item in value[:30]]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _bounded(item, depth=depth + 1)
            for key, item in list(value.items())[:50]
        }
    return value


def _short(value: object, *, depth: int = 0) -> object:
    if depth >= 5:
        return "[depth-limited]"
    if isinstance(value, str):
        return value[:300]
    if isinstance(value, list):
        return [_short(item, depth=depth + 1) for item in value[:60]]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _short(item, depth=depth + 1)
            for key, item in list(value.items())[:50]
        }
    return value


def _compact_enrichment(
    entity_type: str, data: object, *, captured_at: datetime | None = None
) -> dict[str, object]:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (TypeError, ValueError):
            return {}
    if not isinstance(data, dict):
        return {}
    common = {
        key: _bounded(data[key])
        for key in (
            "registered_domain", "subdomain", "suffix", "public_suffix",
            "creation_date", "age_days", "countries", "version", "is_global",
            "is_private", "is_reserved", "asn", "reverse_dns",
        )
        if key in data
    }
    if entity_type == "domain" and captured_at is not None:
        age = domain_age(data, captured_at)
        if age is not None:
            common["age_days"] = age
        else:
            common.pop("age_days", None)
    if entity_type == "domain" and isinstance(data.get("dns"), dict):
        common["dns"] = {
            str(key): (
                {"count": len(value), "present": bool(value)}
                if isinstance(value, list)
                else _bounded(value)
            )
            for key, value in data["dns"].items()
        }
    if data.get("rdap_error"):
        common["rdap_error"] = _bounded(data["rdap_error"])
    return common


_URL_ATTRIBUTES_IN_VALUE = frozenset(
    {"host", "path", "query", "scheme", "fragment", "port"}
)


MAX_URLS_PER_HOST = 4


MAX_ENTITY_VALUE_CHARS = 512


def _compact_attributes(entity_type: str, attributes: object) -> object:
    """Les attributs arrivent parfois en JSON échappé dans une chaîne : décodés,
    ils pèsent moitié moins ; vidés de ce qui redit l'URL, presque rien."""
    if isinstance(attributes, str):
        try:
            attributes = json.loads(attributes)
        except ValueError:
            return _bounded(attributes)
    if not isinstance(attributes, dict):
        return _bounded(attributes)
    if entity_type == "url":
        attributes = {
            key: value
            for key, value in attributes.items()
            if key not in _URL_ATTRIBUTES_IN_VALUE and value not in (None, False, "")
        }
    return _bounded(attributes) if attributes else None


def _compact_entities(
    rows: list[asyncpg.Record], *, captured_at: datetime | None = None
) -> list[dict[str, object]]:
    compact: dict[tuple[str, str], dict[str, object]] = {}
    per_host: dict[str, int] = {}
    omitted_for: dict[str, dict[str, object]] = {}
    for row in rows:
        key = (str(row["entity_type"]), str(row["value_normalized"]))
        if key in compact:
            current = compact[key]
        else:
            if key[0] == "url":
                # Une newsletter porte des dizaines d'URL sur le même hôte
                # (polices, images, liens de suivi) : au-delà de quelques-unes,
                # le juge n'apprend plus rien à les lire, il compte.
                host = key[1].split("/", 3)[2].casefold() if "//" in key[1] else ""
                seen = per_host.get(host, 0)
                per_host[host] = seen + 1
                if seen >= MAX_URLS_PER_HOST:
                    last = omitted_for.get(host)
                    if last is not None:
                        last["more_urls_same_host"] = (
                            int(last.get("more_urls_same_host") or 0) + 1
                        )
                    continue
            current = {
                "entity_type": key[0],
                "value_normalized": key[1][:MAX_ENTITY_VALUE_CHARS],
                "roles": [],
                "enrichment_status": row["enrichment_status"],
                "enrichment_source": row["enrichment_source"],
                "enrichment": _compact_enrichment(
                    key[0], row["enrichment_data"], captured_at=captured_at
                ),
            }
            attributes = _compact_attributes(key[0], row["attributes"])
            if attributes is not None:
                current["attributes"] = attributes
            compact[key] = current
            if key[0] == "url":
                omitted_for[host] = current
        roles = current["roles"]
        role = str(row["role"])
        if isinstance(roles, list) and role not in roles and len(roles) < 12:
            roles.append(role)
    return list(compact.values())[:120]


def _cited_code_articles(
    articles: list[Any], clues: list[Any]
) -> list[dict[str, object]]:
    """Le texte des seuls articles qu'un indice a déclenchés. Un critère qui
    n'est pas un indice n'entre pas au jugement : lui envoyer le Code entier
    ne changeait rien au verdict et doublait le prix de chaque appel."""
    cited = {
        str(clue["article_code"])
        for clue in clues
        if clue.get("article_code")
    }
    return [
        _bounded(dict(article))  # type: ignore[misc]
        for article in articles
        if str(article["article_code"]) in cited
    ]


def _code_index(articles: list[Any]) -> list[dict[str, object]]:
    """Tout le Code de l'édition, une ligne par article : le juge sait ce qui
    existe et peut le nommer, sans en relire le texte à chaque message."""
    return [
        {
            "article_code": str(article["article_code"]),
            "title": str(article["title"] or "")[:120],
        }
        for article in articles
    ]


_DOSSIER_PREFIX_KEYS = ("schema", "privacy", "attack_technique_registry", "code_index")


def _ordered_dossier(dossier: dict[str, object]) -> dict[str, object]:
    ordered = {key: dossier[key] for key in _DOSSIER_PREFIX_KEYS if key in dossier}
    ordered.update(
        (key, value) for key, value in dossier.items() if key not in ordered
    )
    return ordered


def _deduplicate_clues(rows: list[asyncpg.Record]) -> list[dict[str, object]]:
    """Une famille d'indice ne devient pas plusieurs preuves indépendantes."""
    grouped: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        value = dict(row)
        key = (str(value["clue_code"]), str(value["direction"]))
        current = grouped.get(key)
        if current is None or int(value["strength"]) > int(current["strength"]):
            value["occurrence_count"] = int(
                (current or {}).get("occurrence_count", 0)
            ) + 1
            grouped[key] = value
        else:
            current["occurrence_count"] = int(current["occurrence_count"]) + 1
    return sorted(
        grouped.values(),
        key=lambda value: (-int(value["strength"]), str(value["clue_code"])),
    )


def _fit_dossier(
    dossier: dict[str, object], *, max_chars: int | None = None
) -> dict[str, object]:
    if max_chars is None:
        max_chars = MAX_LLM_DOSSIER_CHARS
    dossier["llm_budget"] = {
        "max_chars": max_chars,
        "full_evidence_persisted_locally": True,
        "truncated_for_llm": False,
    }
    if len(_json(dossier)) <= max_chars:
        return dossier
    dossier["llm_budget"]["truncated_for_llm"] = True  # type: ignore[index]
    # La connaissance partait la première, au motif qu'elle n'était qu'un
    # confort d'explication. Depuis qu'elle porte aussi la doctrine adverse,
    # elle est ce qui permet de nommer un montage : la supprimer revenait à
    # juger sans jamais savoir de quelle attaque il s'agit. Elle est donc
    # bornée, plus jetée, et les passages adverses sont gardés d'abord.
    knowledge = dossier.get("reference_knowledge")
    if isinstance(knowledge, dict):
        passages = [p for p in knowledge.get("passages") or [] if isinstance(p, dict)]
        passages.sort(key=lambda p: p.get("nature") != "adversarial")
        knowledge["passages"] = [
            {**passage, "text": str(passage.get("text") or "")[:500]}
            for passage in passages[:4]
        ]
    dossier["attack_technique_registry"] = list(
        dossier.get("attack_technique_registry") or []
    )[:12]
    dossier["entities"] = list(dossier.get("entities") or [])[:60]
    dossier["clues"] = list(dossier.get("clues") or [])[:60]
    dossier["selected_headers"] = list(dossier.get("selected_headers") or [])[:50]
    dossier["authenticated_user_feedback"] = list(
        dossier.get("authenticated_user_feedback") or []
    )[:5]
    dossier["learned_signals"] = list(dossier.get("learned_signals") or [])[:8]
    deep = dossier.get("deep_analysis")
    if isinstance(deep, dict):
        deep["url_analyses"] = list(deep.get("url_analyses") or [])[:10]
        deep["attachment_analyses"] = list(
            deep.get("attachment_analyses") or []
        )[:8]
    message = dossier.get("message")
    if isinstance(message, dict):
        message["body_text"] = str(message.get("body_text") or "")[:8000]
    dossier["llm_budget"]["chars_after_compaction"] = len(_json(dossier))  # type: ignore[index]
    if len(_json(dossier)) > max_chars:
        dossier["entities"] = [
            _short(value) for value in list(dossier.get("entities") or [])[:30]
        ]
        dossier["clues"] = [
            _short(value) for value in list(dossier.get("clues") or [])[:40]
        ]
        dossier["selected_headers"] = [
            _short(value)
            for value in list(dossier.get("selected_headers") or [])[:30]
        ]
        dossier["code_articles"] = [
            _short(value) for value in list(dossier.get("code_articles") or [])
        ]
        if isinstance(deep, dict):
            deep["url_analyses"] = [
                _short(value)
                for value in list(deep.get("url_analyses") or [])[:8]
            ]
            deep["attachment_analyses"] = [
                _short(value)
                for value in list(deep.get("attachment_analyses") or [])[:5]
            ]
        if isinstance(message, dict):
            message["body_text"] = str(message.get("body_text") or "")[:6000]
        dossier["llm_budget"]["chars_after_compaction"] = len(_json(dossier))  # type: ignore[index]
    return dossier
