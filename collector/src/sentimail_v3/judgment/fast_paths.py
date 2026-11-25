"""Voies terminales qualifiées avant les inspections coûteuses."""

from __future__ import annotations

import json
from typing import Any
import asyncpg
import tldextract
from sentimail_v3.observation.dossier.hooks.visible_text import visible_html_text
from sentimail_v3.code.one_time_code import REQUIRED as REQUIRED_ONE_TIME
from sentimail_v3.code.one_time_code import ANCIENNETE_JOURS, excusable_static_risk, express_delivery_reason, shows_one_time_code
from sentimail_v3.code.organisation import authentication_signature
from sentimail_v3.observation.deep_analysis import _domain_organisations
from sentimail_v3.judgment.events import _log

_extract_apex = tldextract.TLDExtract(suffix_list_urls=())
def _apex_of(domain: str) -> str:
    """Réduit un domaine à son apex, sans dépendre d'un service extérieur."""
    value = _extract_apex(domain.casefold().rstrip("."))
    return ".".join(part for part in (value.domain, value.suffix) if part)

def _facts_of(value: object) -> dict[str, object]:
    """Les faits d'un indice, que la base les rende en objet ou en texte."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}

async def _visible_code(pool: asyncpg.Pool[Any], message_id: str) -> bool:
    """Le message montre-t-il un code ? Lu sur le texte que le hook contenu lit :
    l'objet, le texte brut et le texte visible du HTML.

    Le message jugé vient d'être capturé : la rétention à 30 jours (corps
    effacé) ne le concerne jamais ici, seulement les messages historiques
    relus pour la mesure.
    """
    try:
        row = await pool.fetchrow(
            "SELECT subject, body_text, body_html FROM messages WHERE id=$1::uuid",
            message_id,
        )
        if row is None:
            return False
        # Le BOM en tête de sujet est un artefact d'encodage, pas du texte :
        # même geste que le hook contenu sur ce même champ.
        texte = "\n".join(
            (
                str(row["subject"] or "").removeprefix("﻿"),
                str(row["body_text"] or ""),
                visible_html_text(str(row["body_html"] or "")),
            )
        )
        return shows_one_time_code(texte)
    except Exception:  # noqa: BLE001 - fail-soft : constat absent, chemin complet
        _log("verdict.express_signal_failed", message_id=message_id, signal="code_visible")
        return False

async def _sender_established(pool: asyncpg.Pool[Any], message_id: str) -> bool:
    """L'adresse exacte de l'expéditeur a-t-elle déjà été reçue ici ?

    Reçue veut dire : livrée à ce client, authentifiée DMARC, il y a au moins
    ANCIENNETE_JOURS, après un jugement complet, et jamais écartée depuis.
    Une première observation passe ainsi toujours par l'analyse profonde, où
    l'enquêteur sender_relation confronte le nom revendiqué au domaine réel.

    Adresse exacte et pas apex : sur une messagerie partagée, l'apex est livré
    tous les jours et ne dit rien de l'expéditeur. Même client : l'historique
    d'une autre boîte cliente ne décide pas pour celle-ci, comme les lignes
    d'adresse de _history. DMARC sur le précédent : l'adresse a déjà été
    prouvée, pas seulement écrite.

    Le précédent doit porter un verdict de jugement. La voie rapide ne se
    confirme pas elle-même : sans cette clause, le faux avis livré le 1er
    septembre 2026 établirait son adresse pour le suivant. Un message livré
    sans aucun jugement (livraison de secours, ou courrier d'avant le mode
    décisionnel) n'a jamais été examiné non plus : un message relâché ainsi le
    19 août 2026, avec le seul verdict d'observation, suffisait à établir
    l'adresse d'un code reçu le 24 septembre. Le classifieur local compte, car
    il juge le dossier profond.

    Indésirables, spam et dangereux sont exclus, pour la même raison que
    apex_track_record dans _history (25 septembre 2026) : un message rangé ou
    classé contre son expéditeur ne l'établit pas.

    Règle B : la voie rapide passait avant _authenticated_suppression, et un
    correspondant que l'utilisateur a écarté pouvait donc être livré par elle.
    Ce contrôle ferme ce contournement.

    Rétention : clues, investigations et verdicts sont des filles de messages,
    supprimées avec lui à 180 jours. L'effacement à 30 jours ne touche que
    l'EML, les corps et les pièces jointes, jamais from_header, les indices,
    delivery_cases, sender_policies ni labels. Le seuil de sept jours n'est
    donc jamais faussé par la rétention.
    """
    try:
        valeur = await pool.fetchval(
            """
            WITH cur AS (
                SELECT m.id, m.captured_at, m.envelope_recipients[1] AS destinataire,
                       lower(coalesce(substring(m.from_header from '<([^<>]+)>'),
                                      btrim(m.from_header))) AS adresse
                FROM messages m WHERE m.id=$1::uuid
            )
            SELECT coalesce((
                SELECT cur.adresse LIKE '%_@_%'
                   AND EXISTS (
                    SELECT 1 FROM messages p
                    LEFT JOIN delivery_cases d ON d.message_id=p.id
                    WHERE p.id<>cur.id
                      AND p.captured_at <= cur.captured_at - make_interval(days => $2::int)
                      AND p.delivery_status='delivered'
                      AND coalesce(d.state,'')<>'original_filed_as_junk'
                      AND coalesce(d.assessed_classification,'') NOT IN ('spam','dangerous')
                      AND (position('<'||cur.adresse||'>' in lower(p.from_header))>0
                           OR lower(btrim(p.from_header))=cur.adresse)
                      AND EXISTS (SELECT 1 FROM unnest(p.envelope_recipients) r
                                  WHERE sentimail_same_client(r, cur.destinataire))
                      AND EXISTS (SELECT 1 FROM clues c
                                  JOIN investigations i ON i.id=c.investigation_id
                                  WHERE i.message_id=p.id
                                    AND c.clue_code='AUTH_DMARC_PASS')
                      AND NOT EXISTS (SELECT 1 FROM verdicts v
                                      JOIN investigations i ON i.id=v.investigation_id
                                      WHERE i.message_id=p.id
                                        AND v.source='express_path')
                      AND EXISTS (SELECT 1 FROM verdicts v
                                  JOIN investigations i ON i.id=v.investigation_id
                                  WHERE i.message_id=p.id
                                    AND v.source NOT IN ('express_path',
                                                         'observation_pipeline'))
                   )
                   AND NOT EXISTS (
                    SELECT 1 FROM labels l
                    WHERE l.is_ground_truth AND l.active
                      AND l.label IN ('spam','dangerous')
                      AND l.sender_normalized=cur.adresse
                   )
                   AND NOT EXISTS (
                    SELECT 1 FROM sender_policies sp
                    WHERE sp.active AND sp.action='hold'
                      AND sentimail_same_client(cur.destinataire, sp.participant_email)
                      AND ((sp.scope='sender' AND sp.value_normalized=cur.adresse)
                        OR (sp.scope='domain'
                            AND (split_part(cur.adresse,'@',2)=sp.value_normalized
                                 OR right(split_part(cur.adresse,'@',2),
                                          length(sp.value_normalized)+1)
                                    = '.'||sp.value_normalized)))
                   )
                FROM cur
            ), false)
            """,
            message_id,
            ANCIENNETE_JOURS,
        )
        return bool(valeur)
    except Exception:  # noqa: BLE001 - fail-soft : constat absent, chemin complet
        _log("verdict.express_signal_failed", message_id=message_id, signal="established")
        return False

async def _express_judgment(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, object] | None:
    """Le jugement d'un code à usage unique, rendu sans inspection profonde.

    Il n'y a pas de dossier allégé ni de verdict au rabais : le jugement rendu
    ici a la même forme, la même traçabilité et le même chemin d'exécution que
    celui du modèle. Seul le temps change - les indices statiques suffisent à
    conclure sur un courrier dont la forme est aussi contrainte, et les
    quarante-cinq secondes d'inspection profonde rendraient le code périmé.
    """
    indices = await pool.fetch(
        """
        SELECT DISTINCT c.clue_code, c.direction FROM clues c
        JOIN investigations i ON i.id=c.investigation_id
        WHERE i.message_id=$1::uuid
        """,
        message_id,
    )
    codes = {str(row["clue_code"]) for row in indices}
    # Ce que l'observation retient contre le message, quel que soit l'article :
    # la voie rapide se referme sur la charge, pas sur une liste de noms.
    adverse = {
        str(row["clue_code"])
        for row in indices
        if str(row["direction"]) == "adverse"
    }
    if not REQUIRED_ONE_TIME & codes:
        return None
    sender_apex = str(
        await pool.fetchval(
            """
            SELECT split_part(split_part(from_header,'@',2),'>',1)
            FROM messages WHERE id=$1::uuid
            """,
            message_id,
        )
        or ""
    ).strip().casefold()
    # Seuls les liens cliquables comptent comme destinations : une image sur un
    # CDN n'est pas un endroit où l'on va. Le hook d'URL les a déjà réduits à
    # leur apex - « openai.com.evil.top » y devient evil.top, et ne passe donc
    # pas pour un voisin d'openai.com.
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='urls' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    if isinstance(facts, str):
        facts = json.loads(facts)
    if not isinstance(facts, dict) or "actionable_apexes" not in facts:
        # Message analysé avant l'ajout de ce fait : on ne sait pas où mènent
        # ses liens, donc on ne prend pas de raccourci.
        return None
    destinations = [str(value) for value in facts.get("actionable_apexes") or []]
    # Toute la mécanique d'appartenance existait ; personne ne la passait ici.
    # Sans elle, t.co et x.com sont deux tiers, et un code de connexion attend
    # l'examen complet alors que ses liens ne quittent pas son émetteur.
    organisations = await _domain_organisations(pool, message_id)
    signataire = await pool.fetchval(
        """
        SELECT c.facts->>'signing_domain' FROM clues c
        JOIN investigations i ON i.id=c.investigation_id
        WHERE i.message_id=$1::uuid AND c.clue_code='AUTH_DKIM_PASS'
          AND coalesce(c.facts->>'signing_domain','') <> ''
        ORDER BY c.id DESC LIMIT 1
        """,
        message_id,
    )
    if signataire:
        # Une signature valide engage le détenteur du domaine signataire : elle
        # rapproche l'expéditeur de ce domaine-là, et de rien d'autre. La poser
        # aussi sur les destinations les ferait correspondre par construction,
        # ce qui ouvrirait la voie rapide vers n'importe quel tiers.
        marque = authentication_signature(sender_apex, signataire)
        for apex in (_apex_of(sender_apex), _apex_of(str(signataire))):
            if apex and marque:
                organisations.setdefault(apex, set()).update(marque)
    # Un raccourcisseur qui appartient à l'expéditeur ne masque rien de plus
    # que son domaine principal. L'excuse est étroite : elle exige que ce soit
    # le seul motif de risque, sur toutes les URL, et que l'appartenance soit
    # attestée. Le reste des motifs statiques continue de fermer la voie.
    if "URL_STATIC_RISK" in codes:
        risques = [
            _facts_of(row["facts"])
            for row in await pool.fetch(
                """
                SELECT c.facts FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid AND c.clue_code='URL_STATIC_RISK'
                """,
                message_id,
            )
        ]
        if excusable_static_risk(
            risques,
            sender_apex=_apex_of(sender_apex),
            organisations=organisations,
        ):
            codes = codes - {"URL_STATIC_RISK"}
            adverse = adverse - {"URL_STATIC_RISK"}
    # Deux constats que les hooks synchrones ne posent pas. Le 1er septembre
    # 2026, un faux avis de double authentification, sans code et d'une
    # adresse jamais vue, est parti par cette voie.
    code_visible = await _visible_code(pool, message_id)
    established = await _sender_established(pool, message_id)
    reason = express_delivery_reason(
        codes,
        _apex_of(sender_apex),
        destinations,
        organisations,
        adverse,
        established=established,
        code_visible=code_visible,
    )
    # Des booléens seulement : la valeur du code ne s'écrit nulle part.
    _log(
        "verdict.express_considered",
        message_id=message_id,
        established=established,
        code_visible=code_visible,
        granted=reason is not None,
    )
    if reason is None:
        return None
    return {
        "classification": "legitimate",
        "confidence": 0.95,
        "attack": {},
        "delivery_decision": "deliver",
        "rationale": reason,
        "supporting_clue_codes": [],
        "contradicting_clue_codes": sorted(codes & REQUIRED_ONE_TIME),
        "uncertainties": [],
        "requested_additional_evidence": [],
        "unfavorable_case": [],
        "favorable_case": [reason],
        "contested_points": [],
        "missing_harm_elements": [],
        "specialist_assessments": {},
        "verdict_doubt": False,
        "raw_response": {"express_path": "one_time_code"},
    }
