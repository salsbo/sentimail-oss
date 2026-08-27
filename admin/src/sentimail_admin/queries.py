"""Les requêtes, construites à part de leur exécution.

Chaque fonction renvoie le couple (SQL, paramètres) : la construction se teste
sans base, et aucune valeur saisie n'entre jamais dans le texte SQL. Les
colonnes citées ici sont celles de ``database/init`` - rien n'est inventé, et
le corps des messages (``body_text``, ``body_html``, ``raw_eml``) n'est lu par
aucune de ces requêtes.
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple


class Query(NamedTuple):
    sql: str
    params: tuple[Any, ...]


# --- Domaines protégés ------------------------------------------------------

DOMAIN_COLUMNS = (
    "id, fqdn, status, admin_email, verification_token, "
    "verified_at, created_at, updated_at"
)


def list_domains() -> Query:
    return Query(
        f"SELECT {DOMAIN_COLUMNS} FROM domains ORDER BY (status = 'active') DESC, fqdn",
        (),
    )


def insert_domain(fqdn: str, admin_email: str | None) -> Query:
    """Ajout d'un domaine. Il naît en attente : l'activation est un geste à part."""
    return Query(
        "INSERT INTO domains (fqdn, status, admin_email) "
        "VALUES ($1, 'pending', $2) "
        "ON CONFLICT (fqdn) DO NOTHING "
        f"RETURNING {DOMAIN_COLUMNS}",
        (fqdn, admin_email),
    )


def activate_domain(domain_id: str) -> Query:
    """Activation : le domaine protège dès lors tous ses destinataires.

    L'activation ne fabrique jamais la preuve qui lui manque. Un domaine dont
    le jeton n'a pas été constaté en DNS n'est pas activable ici : la
    vérification se fait ailleurs, contre le vrai enregistrement TXT. Sans ce
    garde-fou, un clic ferait analyser le courrier d'un domaine que
    l'exploitant ne contrôle pas.
    """
    return Query(
        "UPDATE domains SET status = 'active', updated_at = now() "
        "WHERE id = $1 AND verified_at IS NOT NULL RETURNING fqdn, status",
        (domain_id,),
    )


def suspend_domain(domain_id: str) -> Query:
    """Suspension : le courrier de ce domaine cesse d'être pris en charge."""
    return Query(
        "UPDATE domains SET status = 'suspended', updated_at = now() "
        "WHERE id = $1 RETURNING fqdn, status",
        (domain_id,),
    )


# --- État d'exploitation ----------------------------------------------------


def operational_status() -> Query:
    return Query(
        "SELECT component, status, details, observed_at "
        "FROM operational_status ORDER BY component",
        (),
    )


def evaluation_report() -> Query:
    """Le rapport de mesure, publie par le collector, lu tel quel.

    La console ne calcule aucun taux : elle n'embarque pas le collector et n'a
    donc pas les fonctions de mesure. Elle affiche ce que le rapport contient,
    y compris ses conditions de validite.
    """
    return Query(
        "SELECT details, observed_at FROM operational_status WHERE component = $1",
        ("evaluation",),
    )


def operational_events(limit: int) -> Query:
    return Query(
        "SELECT component, status, previous_status, reasons, observed_at "
        "FROM operational_events ORDER BY observed_at DESC, id DESC LIMIT $1",
        (limit,),
    )


# --- Courrier récent --------------------------------------------------------


def recent_messages(limit: int, empreinte: str = "") -> Query:
    """Métadonnées seules : jamais le corps, jamais les pièces jointes.

    L'empreinte est le corps d'une référence « M-xxxxxx » : elle réduit la
    liste au seul dossier cité. Le préfixe d'UUID est comparé sur sa forme
    textuelle - la table est bornée par sa rétention, et une référence se
    cherche à l'unité, pas en boucle.
    """
    if empreinte:
        return Query(
            "SELECT id, captured_at, delivered_at, delivery_status, subject, "
            "from_header, envelope_from, envelope_recipients "
            "FROM messages WHERE id::text LIKE $1 || '%' "
            "ORDER BY captured_at DESC LIMIT $2",
            (empreinte, limit),
        )
    return Query(
        "SELECT id, captured_at, delivered_at, delivery_status, subject, "
        "from_header, envelope_from, envelope_recipients "
        "FROM messages ORDER BY captured_at DESC LIMIT $1",
        (limit,),
    )


# --- Registre d'apprentissage ----------------------------------------------


def learning_participants() -> Query:
    """Les destinataires qui ont un registre, avec le volume de chaque part."""
    return Query(
        "SELECT email, sum(regles) AS regles, sum(retours) AS retours FROM ("
        "  SELECT lower(participant_email) AS email, count(*) AS regles,"
        "         0::bigint AS retours"
        "  FROM sender_policies WHERE participant_email IS NOT NULL"
        "  GROUP BY 1"
        "  UNION ALL"
        "  SELECT lower(participant_email), 0::bigint, count(*)"
        "  FROM labels"
        "  WHERE participant_email IS NOT NULL AND is_ground_truth = true"
        "  GROUP BY 1"
        ") registre GROUP BY email ORDER BY email",
        (),
    )


def participant_policies(
    participant_email: str, recherche: str = "", limit: int = 200
) -> Query:
    """Les règles d'un destinataire, filtrables : 682 lignes ne se lisent pas."""
    return Query(
        "SELECT scope, value_normalized, action, active, source, "
        "created_at, updated_at, count(*) OVER () AS total "
        "FROM sender_policies "
        "WHERE lower(participant_email) = $1 "
        "  AND ($2 = '' OR value_normalized ILIKE '%' || $2 || '%') "
        "ORDER BY active DESC, action, value_normalized LIMIT $3",
        (participant_email, recherche, limit),
    )


def participant_labels(participant_email: str, limit: int) -> Query:
    return Query(
        "SELECT label, source, sender_normalized, subject, confidence, "
        "active, created_at FROM labels "
        "WHERE lower(participant_email) = $1 AND is_ground_truth = true "
        "ORDER BY created_at DESC LIMIT $2",
        (participant_email, limit),
    )


# --- Trace des modifications ------------------------------------------------


def audit_entry(
    *,
    action: str,
    target: str,
    client_ip: str,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> Query:
    """La ligne d'audit d'une modification.

    Sans authentification, l'attribution est la seule garantie qui subsiste :
    l'acteur porte l'adresse IP appelante, la charge utile porte la cible et le
    détail du changement. Elle s'écrit dans la transaction de la modification,
    donc jamais l'une sans l'autre.
    """
    payload: dict[str, Any] = {
        "target": target,
        "client_ip": client_ip,
        "interface": "admin_console",
    }
    if user_agent:
        payload["user_agent"] = user_agent[:200]
    if details:
        payload.update(details)
    return Query(
        "INSERT INTO audit_log (actor, action, payload) VALUES ($1, $2, $3::jsonb)",
        (f"admin_console:{client_ip}", action, json.dumps(payload, sort_keys=True)),
    )


# --- Réglages ---------------------------------------------------------------

QUOTA_COLUMNS = (
    "id, fqdn, status, assistant_hourly_limit, assistant_daily_limit, "
    "verdict_hourly_limit, verdict_daily_limit"
)


def list_quotas() -> Query:
    return Query(
        f"SELECT {QUOTA_COLUMNS} FROM domains ORDER BY (status = 'active') DESC, fqdn",
        (),
    )


def update_quotas(
    domain_id: str,
    assistant_hourly: int | None,
    assistant_daily: int | None,
    verdict_hourly: int | None,
    verdict_daily: int | None,
) -> Query:
    """Fixe les plafonds d'un domaine. NULL rend le domaine au défaut commun."""
    return Query(
        "UPDATE domains SET assistant_hourly_limit = $2, "
        "assistant_daily_limit = $3, verdict_hourly_limit = $4, "
        "verdict_daily_limit = $5, updated_at = now() "
        "WHERE id = $1 RETURNING fqdn",
        (domain_id, assistant_hourly, assistant_daily, verdict_hourly, verdict_daily),
    )


def list_local_routing() -> Query:
    return Query(
        "SELECT role, model_name, enabled, fallback_enabled, updated_at "
        "FROM llm_local_routing ORDER BY role",
        (),
    )


def set_local_routing(role: str, model_name: str, enabled: bool) -> Query:
    """Confie un rôle à un modèle local, ou le lui retire.

    Le repli distant n'est pas réglable ici : le retirer expose le service à une
    panne locale, et cette décision demande d'avoir éprouvé le modèle sur la
    durée. Elle reste à la commande d'exploitation.
    """
    return Query(
        "INSERT INTO llm_local_routing "
        "(role, model_name, enabled, fallback_enabled, updated_at) "
        "VALUES ($1, $2, $3, true, now()) "
        "ON CONFLICT (role) DO UPDATE SET model_name = excluded.model_name, "
        "enabled = excluded.enabled, updated_at = now() "
        "RETURNING role, model_name, enabled",
        (role, model_name, enabled),
    )


# --- Moteur de langage -------------------------------------------------------


def role_providers() -> Query:
    """La configuration des deux rôles : jamais la clé, seulement où elle est."""
    return Query(
        "SELECT role, provider, base_url, model_name, token_limit_param, "
        "secret_filename, validated_at, configured_by "
        "FROM llm_role_providers ORDER BY role",
        (),
    )


def set_role_provider(
    role: str,
    provider: str,
    base_url: str,
    model: str,
    token_limit_param: str,
    secret_filename: str,
    body_extras: dict[str, object],
    actor: str,
) -> Query:
    """Enregistre le moteur d'un rôle. La clé vit sur disque, jamais ici.

    La base retient, par rôle, l'adaptateur, l'URL, le modèle, dans quel
    fichier la clé a été posée, et les champs propriétaires qu'un fournisseur
    exige dans le corps de la requête (ex. couper le raisonnement DeepSeek) -
    assez pour que les services la trouvent, rien qui permette de lire la clé.
    """
    return Query(
        "INSERT INTO llm_role_providers "
        "(role, provider, base_url, model_name, token_limit_param, "
        " secret_filename, body_extras, validated_at, configured_by, updated_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now(), $8, now()) "
        "ON CONFLICT (role) DO UPDATE SET provider = EXCLUDED.provider, "
        "base_url = EXCLUDED.base_url, model_name = EXCLUDED.model_name, "
        "token_limit_param = EXCLUDED.token_limit_param, "
        "secret_filename = EXCLUDED.secret_filename, "
        "body_extras = EXCLUDED.body_extras, "
        "validated_at = now(), configured_by = EXCLUDED.configured_by, "
        "updated_at = now() "
        "RETURNING role, provider, model_name",
        (
            role, provider, base_url, model, token_limit_param, secret_filename,
            json.dumps(body_extras or {}, sort_keys=True), actor,
        ),
    )


# --- Identité de l'instance ---------------------------------------------------


def instance_identity_row() -> Query:
    """L'identité déclarée de l'instance, ou rien tant qu'elle n'est pas posée."""
    return Query(
        "SELECT action_address, action_aliases, assistant_sender, "
        "probe_recipient, configured_by, updated_at "
        "FROM instance_identity WHERE singleton = true",
        (),
    )


def set_instance_identity(
    action_address: str,
    aliases: list[str],
    assistant_sender: str,
    probe_recipient: str,
    actor: str,
) -> Query:
    """Enregistre l'identité de l'instance : un singleton, comme le moteur."""
    return Query(
        "INSERT INTO instance_identity "
        "(singleton, action_address, action_aliases, assistant_sender, "
        " probe_recipient, configured_by, updated_at) "
        "VALUES (true, $1, $2, $3, $4, $5, now()) "
        "ON CONFLICT (singleton) DO UPDATE SET "
        "action_address = EXCLUDED.action_address, "
        "action_aliases = EXCLUDED.action_aliases, "
        "assistant_sender = EXCLUDED.assistant_sender, "
        "probe_recipient = EXCLUDED.probe_recipient, "
        "configured_by = EXCLUDED.configured_by, updated_at = now() "
        "RETURNING action_address",
        (action_address, aliases, assistant_sender, probe_recipient, actor),
    )


# --- Sources hostiles --------------------------------------------------------


# Le blocage MX exige 10 occurrences (meme seuil que l'export cote
# collector, hostile_export.BLOCK_THRESHOLD) : en dessous, la source est
# observee, pas bloquee - sauf entree manuelle, qui bloque toujours.
BLOCK_THRESHOLD = 10


def list_hostile_sources(recherche: str = "") -> Query:
    return Query(
        "SELECT ip::text AS ip, hits, first_seen, last_seen, last_reason, rdns, "
        "CASE "
        f"  WHEN last_reason LIKE 'manual%' OR (hits >= {BLOCK_THRESHOLD} "
        "       AND last_seen > now() - interval '30 days') THEN 'bloquee' "
        "  WHEN last_seen > now() - interval '30 days' THEN 'surveillee' "
        "  ELSE 'expiree' END AS etat "
        "FROM hostile_smtp_sources "
        "WHERE $1 = '' OR ip::text ILIKE '%' || $1 || '%' "
        "   OR last_reason ILIKE '%' || $1 || '%' "
        "   OR coalesce(rdns, '') ILIKE '%' || $1 || '%' "
        "ORDER BY hits DESC, last_seen DESC LIMIT 500",
        (recherche,),
    )


def count_active_hostile_sources() -> Query:
    return Query(
        "SELECT count(*) AS actives FROM hostile_smtp_sources "
        "WHERE last_reason LIKE 'manual%' "
        f"   OR (hits >= {BLOCK_THRESHOLD} "
        "       AND last_seen > now() - interval '30 days')",
        (),
    )


def insert_hostile_source(network: str) -> Query:
    """Ajout manuel : l'entrée ne expire jamais d'elle-même."""
    return Query(
        "INSERT INTO hostile_smtp_sources (ip, last_reason) "
        "VALUES ($1::inet, 'manual_admin') "
        "ON CONFLICT (ip) DO NOTHING RETURNING ip::text",
        (network,),
    )


def delete_hostile_source(network: str) -> Query:
    return Query(
        "DELETE FROM hostile_smtp_sources WHERE ip=$1::inet RETURNING ip::text",
        (network,),
    )


# --- Écarts humain/modèle ----------------------------------------------------


def discrepancy_metrics() -> Query:
    """Les écarts par sens, sur 7 et 30 jours, acquittés compris.

    L'acquittement classe le dossier, il ne réécrit pas la mesure : ces
    compteurs incluent toujours tous les écarts.
    """
    return Query(
        "SELECT direction, "
        "  count(*) FILTER (WHERE created_at > now() - interval '7 days') AS j7, "
        "  count(*) FILTER (WHERE created_at > now() - interval '30 days') AS j30, "
        "  count(*) FILTER (WHERE acknowledged_at IS NULL) AS ouverts "
        "FROM discrepancies GROUP BY direction",
        (),
    )


# Instruire un écart demande de savoir ce qui a pesé contre le message, dit en
# clair - pas la liste de tout ce que le dossier a observé. Les indices à
# charge et l'état de la chaîne profonde suffisent à expliquer un désaccord :
# c'est ce que le moteur avait à opposer, et ce qu'il n'a pas pu vérifier.
# Tant que le message existe, ils viennent de sa propre enquête ; après sa
# purge, ils manquent et l'écart se lit sur ses colonnes propres.
_ECARTS_COLONNES = (
    "SELECT d.id::text AS id, d.message_id::text AS message_id, d.direction, "
    "d.human_label, d.model_classification, d.model_confidence, "
    "d.model_rationale, d.created_at, d.acknowledged_at, d.acknowledged_by, "
    "l.participant_email, l.sender_normalized, l.context::text AS label_context, "
    "coalesce(l.subject, m.subject) AS subject, "
    "enquete.charges::text AS charges, enquete.deep_complete AS deep_complete, "
    "enquete.blocage::text AS blocage "
    "FROM discrepancies d "
    "LEFT JOIN labels l ON l.id = d.label_id "
    "LEFT JOIN messages m ON m.id = d.message_id "
    "LEFT JOIN LATERAL ("
    "  SELECT (i.summary->>'deep_analysis_complete')::boolean AS deep_complete,"
    "         (SELECT jsonb_agg(jsonb_build_object("
    "                   'code', c.clue_code, 'statement', c.statement,"
    "                   'strength', c.strength) ORDER BY c.strength DESC)"
    "            FROM clues c"
    "           WHERE c.investigation_id = i.id"
    "             AND c.direction = 'adverse') AS charges,"
    # Ce qui a interdit la livraison, quand le jugement a été rejeté avant de
    # devenir contraignant : c'est le fait immuable du dossier, celui qui a
    # transformé une conclusion en question. Sans lui, l'écart est illisible.
    "         (SELECT vr.response->'verdict'->'structural_contradiction'"
    "            FROM verdict_runs vr"
    "           WHERE vr.investigation_id = i.id"
    "           ORDER BY vr.created_at DESC LIMIT 1) AS blocage"
    "    FROM investigations i"
    "   WHERE i.message_id = d.message_id"
    "   ORDER BY i.started_at DESC LIMIT 1"
    ") enquete ON true "
)


def list_discrepancies(traites: bool, limit: int) -> Query:
    """Les écarts, ouverts ou traités, avec les éléments des deux jugements.

    Les colonnes du label et la copie du raisonnement survivent à la purge du
    message d'origine ; le sujet du message reste un secours. Le contexte du
    label porte les critères retenus (codes d'indices), leur traduction, et
    les mots mêmes du jugement humain."""
    return Query(
        _ECARTS_COLONNES
        + "WHERE (d.acknowledged_at IS NOT NULL) = $1 "
        "ORDER BY d.created_at DESC LIMIT $2",
        (traites, limit),
    )


def discrepancy_by_reference(empreinte: str, limit: int) -> Query:
    """L'écart cité par sa référence, qu'il soit ouvert ou déjà traité.

    Citer une référence, c'est désigner un dossier précis : le partage entre
    « à traiter » et « traités » n'a plus de sens à ce moment-là, il ferait
    seulement répondre « introuvable » à une référence parfaitement valide.
    """
    return Query(
        _ECARTS_COLONNES
        + "WHERE d.id::text LIKE $1 || '%' "
        "ORDER BY d.created_at DESC LIMIT $2",
        (empreinte, limit),
    )


def acknowledge_discrepancy(discrepancy_id: str, who: str) -> Query:
    """Acquitte un écart encore ouvert ; un écart déjà traité ne bouge plus."""
    return Query(
        "UPDATE discrepancies SET acknowledged_at = now(), acknowledged_by = $2 "
        "WHERE id = $1::uuid AND acknowledged_at IS NULL RETURNING id::text",
        (discrepancy_id, who),
    )
