"""Ce que les qualifications humaines apprennent au corpus.

Un utilisateur qui classe trois messages venus de trois expéditeurs différents
en disant la même chose de chacun ne juge pas trois expéditeurs : il décrit un
mécanisme. C'est ce mécanisme qu'il faut inscrire, pas les adresses - une
adresse jetable ne resservira jamais, le montage si.

Trois garde-fous, parce qu'un corpus qui s'écrit tout seul est aussi un corpus
qu'on peut empoisonner :

- il faut plusieurs expéditeurs distincts, sinon on grave une habitude locale
  en règle générale ;
- il faut une qualification constante ; un même profil dit tantôt légitime,
  tantôt indésirable ne décrit rien, et l'inscrire figerait une erreur ;
- la fiche est rédigée par gabarit, jamais par un modèle. Le texte ne contient
  donc que des faits comptés et les codes d'indices observés : rien qui puisse
  être inventé, et rien que l'on ne puisse remonter à ses sources.

Une fiche apprise vaut ce que vaut son observation : elle nomme un motif, elle
ne prouve aucun fait sur un message. Elle reste révocable, et elle cite les
messages qui l'ont produite pour qu'on puisse toujours la contester.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

MIN_MESSAGES = 3
MIN_SENDERS = 2
MIN_SHARED_SIGNALS = 2
MAX_SIGNALS = 8
ADVERSE_LABELS = frozenset({"spam", "dangerous", "suspect"})


@dataclass(frozen=True)
class Profile:
    """Un motif observé : ce qui se répète, combien de fois, chez qui."""

    label: str
    signals: tuple[str, ...]
    message_count: int
    sender_count: int
    first_seen: str
    last_seen: str
    message_ids: tuple[str, ...] = field(default=())

    @property
    def identifier(self) -> str:
        return "appris-" + "-".join(
            part.casefold().replace("_", "-") for part in self.signals[:3]
        )


def _entries(labels: list[dict[str, object]]) -> list[dict[str, object]]:
    kept: list[dict[str, object]] = []
    for entry in labels:
        signals = [str(value) for value in entry.get("signals") or []]
        if len(signals) < MIN_SHARED_SIGNALS:
            continue
        kept.append({**entry, "signals": signals})
    return kept


def recurring_profiles(labels: list[dict[str, object]]) -> list[Profile]:
    """Les motifs assez répétés, assez constants et assez larges pour être écrits."""
    entries = _entries(labels)
    if len(entries) < MIN_MESSAGES:
        return []
    counter: Counter[str] = Counter()
    for entry in entries:
        counter.update(set(entry["signals"]))  # type: ignore[arg-type]
    # Le socle commun : les indices présents dans la grande majorité des
    # messages qualifiés. Un indice qui n'apparaît qu'une fois décrit un
    # message, pas un motif.
    threshold = max(MIN_MESSAGES, int(len(entries) * 0.7))
    shared = tuple(
        sorted(code for code, count in counter.items() if count >= threshold)
    )
    if len(shared) < MIN_SHARED_SIGNALS:
        return []
    concerned = [
        entry for entry in entries if set(shared).issubset(set(entry["signals"]))  # type: ignore[arg-type]
    ]
    if len(concerned) < MIN_MESSAGES:
        return []
    verdicts = {str(entry.get("label")) for entry in concerned}
    if len(verdicts) != 1:
        return []
    label = verdicts.pop()
    if label not in ADVERSE_LABELS:
        return []
    senders = {str(entry.get("sender_normalized") or "") for entry in concerned}
    if len(senders) < MIN_SENDERS:
        return []
    dates = sorted(str(entry.get("observed_on") or "") for entry in concerned)
    return [
        Profile(
            label=label,
            signals=shared[:MAX_SIGNALS],
            message_count=len(concerned),
            sender_count=len(senders),
            first_seen=dates[0],
            last_seen=dates[-1],
            message_ids=tuple(str(entry.get("message_id") or "") for entry in concerned)[:12],
        )
    ]


def render_note(profile: Profile) -> str:
    """La fiche, en sections numérotées comme le reste du corpus."""
    signals = "\n".join(f"  - {code}" for code in profile.signals)
    qualification = {
        "spam": "indésirable",
        "dangerous": "dangereux",
        "suspect": "douteux",
    }.get(profile.label, profile.label)
    return f"""MOTIF OBSERVE : {qualification.upper()} RECURRENT

Fiche produite à partir de qualifications humaines. Elle décrit ce qui s'est
répété, et rien d'autre.

1. Ce qui se répète

Les indices suivants ont accompagné ensemble {profile.message_count} messages
qualifiés « {qualification} » par le destinataire, émis par
{profile.sender_count} expéditeurs distincts, entre le {profile.first_seen} et
le {profile.last_seen} :

{signals}

2. Comment lire ce motif

La présence de ces indices sur un nouveau message signale une ressemblance avec
un ensemble déjà écarté par le destinataire. Cette ressemblance ne prouve rien
par elle-même : elle ne constate aucun fait, et un message peut la présenter
tout en étant parfaitement légitime. Les faits restent établis par les indices
du dossier, jamais par cette fiche.

3. Origine et portée

Cette fiche vient d'une observation, non d'une norme ni d'une analyse
technique. Elle a été produite automatiquement à partir de
{profile.message_count} qualifications concordantes. Si le destinataire
qualifie autrement des messages portant le même profil, elle cesse d'être
exacte et doit être retirée.
"""


async def store_note(
    pool: Any,
    profile: Profile,
    *,
    client: Any = None,
    base_url: str = "",
    model: str = "",
) -> str:
    """Inscrit la fiche au corpus, sous une nature qui la distingue.

    « learned » n'est ni « normative » ni « adversarial » : le juge doit savoir
    qu'il lit une observation locale, révocable, et non une norme ni une
    doctrine écrite à la main.
    """
    from sentimail_v3.code.knowledge import _pack, embed, split_sections

    body = render_note(profile)
    title = (
        f"Motif observé : {profile.label} récurrent "
        f"({', '.join(profile.signals[:2])})"
    )
    document_id = await pool.fetchval(
        """
        INSERT INTO knowledge_documents (
            source_id, title, url, topic, nature, sha256, captured_on
        ) VALUES ($1,$2,$3,$4,'learned',$5,$6::date)
        ON CONFLICT (source_id) DO UPDATE SET
            title=excluded.title, sha256=excluded.sha256,
            captured_on=excluded.captured_on
        RETURNING id
        """,
        profile.identifier,
        title,
        "sentimail://doctrine-apprise/" + profile.identifier,
        "motif observé",
        hashlib.sha256(body.encode("utf-8")).hexdigest(),
        profile.last_seen,
    )
    await pool.execute(
        "DELETE FROM knowledge_chunks WHERE document_id=$1", document_id
    )
    for ordinal, (section, chunk) in enumerate(split_sections(body)):
        vector = None
        if client is not None and base_url and model:
            vector = await embed(client, base_url, model, f"{title} {section}\n{chunk}")
        await pool.execute(
            """
            INSERT INTO knowledge_chunks (
                document_id, ordinal, section, body, embedding, embedding_model
            ) VALUES ($1,$2,$3,$4,$5,$6)
            """,
            document_id,
            ordinal,
            section,
            chunk,
            _pack(vector) if vector else None,
            model if vector else None,
        )
    return profile.identifier


async def refresh_learned_doctrine(
    pool: Any,
    *,
    client: Any = None,
    base_url: str = "",
    model: str = "",
) -> list[str]:
    """Relit les qualifications humaines et met à jour les fiches apprises.

    Le calcul se fait par destinataire : ce que l'un écarte n'engage pas
    l'autre, et deux personnes n'ont pas le même courrier ordinaire.
    """
    participants = [
        str(row["participant_email"])
        for row in await pool.fetch(
            """
            SELECT participant_email, count(*) AS total
            FROM labels
            WHERE is_ground_truth=true AND active=true
            GROUP BY 1 HAVING count(*) >= $1
            """,
            MIN_MESSAGES,
        )
    ]
    written: list[str] = []
    for participant in participants:
        rows = await pool.fetch(
            """
            SELECT l.label, l.sender_normalized, l.message_id::text AS message_id,
                   l.created_at::date::text AS observed_on,
                   coalesce(l.context->'signals','[]'::jsonb) AS signals
            FROM labels l
            WHERE l.is_ground_truth=true AND l.active=true
              AND sentimail_same_client(l.participant_email,$1)
              AND l.created_at > now() - interval '180 days'
            ORDER BY l.created_at DESC
            LIMIT 500
            """,
            participant,
        )
        labels = [
            {
                "label": str(row["label"]),
                "sender_normalized": str(row["sender_normalized"] or ""),
                "message_id": str(row["message_id"] or ""),
                "observed_on": str(row["observed_on"] or ""),
                "signals": _signal_list(row["signals"]),
            }
            for row in rows
        ]
        for profile in recurring_profiles(labels):
            written.append(
                await store_note(
                    pool, profile, client=client, base_url=base_url, model=model
                )
            )
    return written


def _signal_list(value: object) -> list[str]:
    if isinstance(value, str):
        import json

        try:
            value = json.loads(value)
        except ValueError:
            return []
    return [str(item) for item in value] if isinstance(value, list) else []
