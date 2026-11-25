"""Mesure sur des constats conservés, sans écrire en base ni visiter les liens.

Utilise uniquement le fournisseur déjà configuré pour SentiMail. Les groupes
non annotés restent des témoins, jamais une vérité humaine inventée. Exécuter
dans l'environnement collector, avec la version candidate chargée en mémoire.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from email.utils import parseaddr
import json
from types import SimpleNamespace

import asyncpg
import httpx

from sentimail_v3.config import load_settings
from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.sender_relation import published_activity
from sentimail_v3.observation.dossier.hooks.visible_text import readable_text
from sentimail_v3.observation.deep_hooks import ActionDestinationHook, SenderActivityHook
from sentimail_v3.judgment.verdict_engine import _build_dossier, _cited_code_articles, _code_index, _prepare_for_judgment, _prompt, _parse_final_response
from sentimail_v3.llm import provider_chat_json


def obj(value):
    return json.loads(value) if isinstance(value, str) else (value or {})


async def main():
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5,
                                   server_settings={"default_transaction_read_only": "on"})
    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0 (compatible)"}, timeout=30) as client:
        rows = await pool.fetch("""
            SELECT m.id::text,m.subject,m.from_header,m.body_text,m.body_html,
                   i.id AS investigation_id,hr.facts AS deep, l.label,
                   dc.details->'final_judgment'->>'delivery_decision' AS old_decision
            FROM messages m JOIN investigations i ON i.message_id=m.id
            JOIN hook_runs hr ON hr.investigation_id=i.id AND hr.hook_name='deep_evidence'
            LEFT JOIN LATERAL (
                SELECT label FROM labels WHERE message_id=m.id AND is_ground_truth AND active
                ORDER BY created_at DESC LIMIT 1
            ) l ON true
            LEFT JOIN delivery_cases dc ON dc.message_id=m.id
            WHERE m.captured_at>now()-interval '29 days'
              AND coalesce(m.body_text,m.body_html,'')<>''
              AND (l.label IS NOT NULL OR m.subject ~* '(parcel|colis|livraison|delivery|shipment)'
                   OR EXISTS (SELECT 1 FROM clues WHERE investigation_id=i.id AND clue_code='SENDER_WITHOUT_PUBLIC_FOOTPRINT'))
            ORDER BY m.captured_at DESC
        """)
        groups = Counter()
        selected, seen = [], Counter()
        limits = {"reported_false": 1, "human_legitimate": 25, "human_adverse": 20, "parcel_control": 15, "unknown_identity_control": 15}
        for row in rows:
            deep = obj(row["deep"])
            codes = {s.get("clue_code") for s in deep.get("signals", []) if isinstance(s, dict)}
            if row["id"].startswith("9845a984"):
                group = "reported_false"
            elif row["label"] == "legitimate":
                group = "human_legitimate"
            elif row["label"] in {"spam", "dangerous", "suspect"}:
                group = "human_adverse"
            elif "SENDER_WITHOUT_PUBLIC_FOOTPRINT" in codes:
                group = "unknown_identity_control"
            elif row["old_decision"] == "deliver":
                group = "parcel_control"
            else:
                continue
            sender = parseaddr(row["from_header"] or "")[1]
            if groups[group] >= limits[group] or seen[(group, sender)] >= 2:
                continue
            groups[group] += 1
            seen[(group, sender)] += 1
            selected.append((row, group))
        print(json.dumps({"selected": dict(groups), "readonly": True, "links_revisited": False}), flush=True)
        articles = [dict(r) for r in await pool.fetch("SELECT article_code,title,principle,default_direction,default_strength,severity,limitations,parameters FROM code_articles WHERE enabled AND edition_id IN (SELECT id FROM code_editions WHERE status='active')")]
        articles += globals().get("VALIDATION_ARTICLES", [])
        # Le banc ne déclenche aucune nouvelle recherche publique.
        from sentimail_v3.observation import organisation_search
        async def cached_about_domain(pool, client, settings, apex):
            result = await pool.fetchval("SELECT results FROM search_lookups WHERE query_key=$1", "domaine:" + apex)
            return obj(result) if result else []
        organisation_search.about_domain = cached_about_domain
        semaphore = asyncio.Semaphore(3)

        async def evaluate(row, group):
            async with semaphore:
                deep = obj(row["deep"])
                stored = [dict(r) for r in await pool.fetch(
                    "SELECT clue_code,article_code,direction,strength,facts,statement FROM clues WHERE investigation_id=$1", row["investigation_id"])]
                old_codes = {c["clue_code"] for c in stored}
                history = deep.get("history") or {}
                apex = str(history.get("sender_apex") or history.get("sender_domain") or "")
                activity = next((obj(c["facts"]).get("published_activity") or obj(c["facts"]).get("facts", {}).get("published_activity") for c in stored if c["clue_code"] in {"SENDER_ACTIVITY_COHERENT", "SENDER_ACTIVITY_INCOHERENT"}), "")
                site_source = any(
                    run.get("hook_name") == "sender_relation" and obj(run.get("facts")).get("activity_source") == "site"
                    for run in deep.get("deep_hook_runs", [])
                )
                # Une ancienne attribution tirée d'une recherche non filtrée
                # n'est pas une page d'accueil. Elle repasse par le filtre exact.
                if not site_source:
                    activity = ""
                if not activity:
                    search = await pool.fetchval("SELECT results FROM search_lookups WHERE query_key=$1", "domaine:" + apex)
                    activity, _ = published_activity(None, obj(search) if search else [], from_apex=apex)
                context = SimpleNamespace(
                    pool=pool, client=client, settings=settings, sender_apex=apex,
                    message_id=row["id"],
                    subject=row["subject"] or "", body=readable_text(row["body_text"], row["body_html"])[0],
                    display_name=parseaddr(row["from_header"] or "")[0], clue_codes=old_codes,
                    url_analyses=deep.get("url_analyses") or [], sender_site={"text": activity} if activity else None,
                )
                # Aucun rappel de recherche ni de site : le métier absent reste
                # non conclu. Les erreurs d'identité anciennes ne sont pas réécrites.
                activity_clues, _ = await SenderActivityHook().observe(context)
                destination_clues, facts = await ActionDestinationHook().observe(context)
                new_codes = {code for code in old_codes if not code.startswith("CORRELATION_") and code not in {"SENDER_ACTIVITY_COHERENT", "SENDER_ACTIVITY_INCOHERENT"}} | {c["clue_code"] for c in activity_clues + destination_clues}
                correlated = correlations(new_codes)
                review = any(c["article_code"] == "CORR-019" for c in correlated)
                new_decision = row["old_decision"]
                new_classification = None
                judge_error = None
                changed_adverse = [c for c in activity_clues + destination_clues if c["direction"] == "adverse" and c["clue_code"] not in old_codes]
                removed_adverse = "SENDER_ACTIVITY_INCOHERENT" in old_codes and "SENDER_ACTIVITY_INCOHERENT" not in new_codes
                if changed_adverse or removed_adverse:
                    dossier = await _build_dossier(pool, str(row["investigation_id"]), deep)
                    # Les constats refaits remplacent leurs anciennes versions,
                    # sans réécrire aucun dossier opérationnel.
                    replacements = {c["clue_code"] for c in activity_clues + destination_clues}
                    if activity_clues:
                        replacements |= {"SENDER_ACTIVITY_COHERENT", "SENDER_ACTIVITY_INCOHERENT"}
                    dossier["clues"] = [c for c in dossier["clues"] if c["clue_code"] not in replacements and not c["clue_code"].startswith("CORRELATION_")]
                    dossier["clues"] += activity_clues + destination_clues
                    existing = {c["clue_code"] for c in dossier["clues"]}
                    dossier["clues"] += [c for c in correlated if c["clue_code"] not in existing]
                    dossier["code_index"] = _code_index(articles)
                    dossier["code_articles"] = _cited_code_articles(articles, dossier["clues"])
                    dossier = _prepare_for_judgment(dossier, deep, settings)
                    try:
                        content, _ = await provider_chat_json(pool, client, settings, messages=_prompt(dossier), max_tokens=3000, role="verdict", allow_local=False)
                        judgment, _ = _parse_final_response(content, dossier)
                        new_decision, new_classification = judgment["delivery_decision"], judgment["classification"]
                    except Exception as exc:
                        judge_error = type(exc).__name__
                        new_decision = "invalid"
                result = {
                    "id": row["id"], "group": group, "human_label": row["label"],
                    "old_decision": row["old_decision"], "destination_status": facts.get("status"),
                    "destination_facts": facts, "new_activity_codes": [c["clue_code"] for c in activity_clues],
                    "activity_available": bool(activity), "review_required": review,
                    "activity_clues": activity_clues,
                    "candidate_decision": new_decision, "candidate_classification": new_classification,
                    "judge_recalled": bool(changed_adverse or removed_adverse), "judge_error": judge_error,
                    "new_review": new_decision == "ask_user" and row["old_decision"] == "deliver",
                    "destination_statement": destination_clues[0]["statement"] if destination_clues else "",
                }
                print(json.dumps(result, ensure_ascii=False), flush=True)
                return result

        results = await asyncio.gather(*(evaluate(row, group) for row, group in selected))
        print(json.dumps({"summary": {
            "groups": dict(groups), "destination_statuses": dict(Counter(r["destination_status"] for r in results)),
            "new_reviews_by_group": dict(Counter(r["group"] for r in results if r["new_review"])),
            "contradictions_by_group": dict(Counter(r["group"] for r in results if r["destination_status"] == "contradictory")),
            "activity_available": sum(r["activity_available"] for r in results),
            "activity_incoherent_by_group": dict(Counter(r["group"] for r in results if "SENDER_ACTIVITY_INCOHERENT" in r["new_activity_codes"])),
            "judge_calls": sum(r["judge_recalled"] for r in results),
            "judge_errors": sum(bool(r["judge_error"]) for r in results),
        }}, ensure_ascii=False), flush=True)
    await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
