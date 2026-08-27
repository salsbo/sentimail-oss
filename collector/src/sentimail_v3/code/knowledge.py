"""Chercher dans les normes de la messagerie, sans jamais en faire une preuve.

Un modèle sait à peu près ce qu'est DMARC. « À peu près » suffit à expliquer de
travers, à inventer un paragraphe et à citer une règle qui n'existe pas. Les
documents de référence sont donc figés dans le dépôt, découpés en sections et
interrogeables : ce que MAIA affirme d'une norme, elle peut le montrer.

La recherche se fait en deux temps. Postgres rappelle largement, par les mots :
ça fonctionne toujours, y compris sans le moindre service externe. Puis, si un
modèle d'embeddings local répond, ces candidats sont reclassés par proximité de
sens — c'est ce qui rattrape une question posée avec d'autres mots que ceux du
texte. Si l'embedding est indisponible, l'ordre lexical reste, et la réponse
aussi : la dégradation ne fait jamais disparaître la connaissance.

Une limite, tenue par le reste du système et rappelée ici : ces extraits
expliquent, ils ne prouvent rien. Aucun passage de RFC ne crée un indice, ne
lève une barrière matérielle ni ne modifie un verdict.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import asyncpg
import httpx

MANIFEST_NAME = "manifest.json"
MAX_CHUNK_CHARS = 1600
MIN_CHUNK_CHARS = 240
LEXICAL_CANDIDATES = 300
# En dessous, le rappel par les mots n'a rien trouvé d'exploitable : c'est le
# cas d'une question posée en français sur un texte anglais (« désabonnement »
# n'apparaît dans aucune RFC). On repart alors du corpus entier, par le sens.
LEXICAL_FLOOR = 20
SEMANTIC_SWEEP = 5000
_SECTION = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(\S.{0,110})$")
# Le pied de page porte le nom de l'auteur avant le numéro : le motif
# doit prendre la ligne entière, pas seulement le crochet final.
_PAGE_BREAK = re.compile(r"\[Page \d+\]\s*$|^\f")
_RUNNING_HEAD = re.compile(r"^RFC \d+\s{2,}.*\d{4}\s*$")
# Le bloc administratif de première page : ni norme, ni explication, il ne
# ferait que remonter sur des mots comme « standards » ou « category ».
_FRONT_MATTER = re.compile(
    r"^(Network Working Group|Internet Engineering Task Force|Request for "
    r"Comments:|Category:|ISSN:|Obsoletes:|Updates:|Expires:|Intended status:)",
)
_WORD = re.compile(r"[A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9_.-]{1,30}")
# Une bibliographie, un registre IANA ou des remerciements n'expliquent rien.
# Indexés, ils occupent des places comptées dans les résultats et remontent sur
# n'importe quelle question, faute de contenu propre.
_UNINFORMATIVE = re.compile(
    r"^\d[\d.]*\.?\s+(normative|informative)?\s*references\b"
    r"|^\d[\d.]*\.?\s+iana considerations\b"
    r"|^\d[\d.]*\.?\s+acknowledge?ments?\b"
    r"|^\d[\d.]*\.?\s+(authors?|contributors?)[\u2019\']? addresses\b"
    r"|^\d[\d.]*\.?\s+table of contents\b"
    r"|^\d[\d.]*\.?\s+index\b"
    r"|^\d[\d.]*\.?\s+full copyright\b",
    re.IGNORECASE,
)
# Ces mots ne discriminent rien : les garder ferait remonter n'importe quelle
# section au seul motif qu'elle contient « message » ou « the ».
_NOISE = {
    "a", "au", "aux", "avec", "ce", "cet", "cette", "comment", "dans", "de",
    "des", "du", "en", "est", "et", "il", "je", "la", "le", "les", "ma", "me",
    "mon", "ne", "on", "ou", "par", "pas", "peux", "pour", "pourquoi", "que",
    "quel", "quelle", "qui", "quoi", "sa", "se", "ses", "son", "sur", "ta",
    "te", "tes", "ton", "tu", "un", "une", "veux", "and", "are", "can", "does",
    "for", "how", "is", "it", "of", "or", "the", "to", "what", "why", "with",
    "mail", "email", "message", "messages", "courriel",
}


@dataclass(frozen=True)
class Passage:
    """Un extrait citable : d'où il vient, et ce qu'il dit."""

    source_id: str
    title: str
    section: str
    body: str
    url: str


def _clean(raw: str) -> list[str]:
    lines: list[str] = []
    for line in raw.replace("\r\n", "\n").split("\n"):
        stripped = line.rstrip()
        if (
            _PAGE_BREAK.search(stripped)
            or _RUNNING_HEAD.match(stripped)
            or _FRONT_MATTER.match(stripped)
        ):
            continue
        lines.append(stripped)
    return lines


def _bounded_paragraphs(body: str) -> list[str]:
    """Découpe les blocs qu'aucune ligne vide ne sépare, comme les sommaires.

    Sans cela, un paragraphe unique de plusieurs milliers de caractères
    traversait la borne intact : trop gros pour être un extrait utile, et assez
    gros pour faire échouer certains moteurs d'embedding.
    """
    parts: list[str] = []
    for paragraph in body.split("\n\n"):
        if len(paragraph) <= MAX_CHUNK_CHARS:
            parts.append(paragraph)
            continue
        lines = paragraph.split("\n")
        buffer: list[str] = []
        size = 0
        for line in lines:
            if size + len(line) > MAX_CHUNK_CHARS and buffer:
                parts.append("\n".join(buffer))
                buffer, size = [], 0
            buffer.append(line)
            size += len(line) + 1
        if buffer:
            parts.append("\n".join(buffer))
    return parts


def split_sections(raw: str) -> list[tuple[str, str]]:
    """Découpe un document en sections numérotées, puis borne leur taille."""
    sections: list[tuple[str, list[str]]] = []
    current_title = "Préambule"
    current: list[str] = []
    for line in _clean(raw):
        match = _SECTION.match(line)
        if match and not line.startswith(" "):
            if current:
                sections.append((current_title, current))
            current_title = f"{match.group(1)}. {match.group(2).strip()}"
            current = []
        else:
            current.append(line)
    if current:
        sections.append((current_title, current))

    chunks: list[tuple[str, str]] = []
    for title, body_lines in sections:
        if _UNINFORMATIVE.match(title):
            continue
        body = "\n".join(body_lines).strip()
        body = re.sub(r"\n{3,}", "\n\n", body)
        if len(body) < MIN_CHUNK_CHARS:
            # Une section trop courte est un titre, une note ou un renvoi :
            # seule, elle n'apprend rien et pollue les résultats.
            continue
        if len(body) <= MAX_CHUNK_CHARS:
            chunks.append((title, body))
            continue
        piece: list[str] = []
        size = 0
        part = 1
        for paragraph in _bounded_paragraphs(body):
            if size + len(paragraph) > MAX_CHUNK_CHARS and piece:
                chunks.append((f"{title} ({part})", "\n\n".join(piece)))
                piece, size, part = [], 0, part + 1
            piece.append(paragraph)
            size += len(paragraph) + 2
        if piece:
            chunks.append((f"{title} ({part})", "\n\n".join(piece)))
    return chunks


def _pack(vector: list[float]) -> bytes:
    """Vecteur normalisé et sérialisé : la similarité devient un produit."""
    norm = math.sqrt(sum(value * value for value in vector)) or 1.0
    return struct.pack(f"{len(vector)}f", *(value / norm for value in vector))


def _unpack(blob: bytes) -> list[float]:
    return list(struct.unpack(f"{len(blob) // 4}f", blob))


def _similarity(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


async def embed(
    client: httpx.AsyncClient, base_url: str, model: str, text: str
) -> list[float] | None:
    """Vecteur d'un texte, ou rien : un embedding absent n'est pas une panne."""
    # Deux tentatives, et surtout deux réglages. Le batch élargi est un
    # contournement propre à certains modèles dont l'entrée doit tenir d'un
    # bloc ; sur d'autres, il fait planter le moteur sur les textes longs.
    # Aucun des deux ne convient partout : on essaie le réglage par défaut,
    # puis l'autre.
    for options in (None, {"num_batch": 8192}):
        payload: dict[str, Any] = {"model": model, "prompt": text[:8000]}
        if options:
            payload["options"] = options
        try:
            response = await client.post(
                f"{base_url.rstrip('/')}/api/embeddings",
                json=payload,
                # Le premier appel charge le modèle en mémoire et peut être
                # long ; les suivants se comptent en millisecondes.
                timeout=180.0,
            )
            response.raise_for_status()
            vector = response.json().get("embedding")
        except (httpx.HTTPError, ValueError, KeyError):
            continue
        if isinstance(vector, list) and vector:
            return [float(value) for value in vector]
    return None


async def load_directory(
    pool: asyncpg.Pool[Any],
    directory: Path,
    *,
    client: httpx.AsyncClient | None = None,
    base_url: str = "",
    model: str = "",
) -> dict[str, int]:
    """Charge le contenu figé du dépôt, sans jamais rien télécharger."""
    manifest = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    loaded = skipped = passages = embedded = 0
    for entry in manifest.get("documents", []):
        path = directory / str(entry["path"])
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"empreinte incohérente pour {entry['id']}")
        known = await pool.fetchrow(
            """
            SELECT d.sha256,
                   (
                       SELECT count(*) FROM knowledge_chunks c
                       WHERE c.document_id=d.id
                         AND c.embedding_model IS DISTINCT FROM $2
                   ) AS foreign_vectors
            FROM knowledge_documents d WHERE d.source_id=$1
            """,
            entry["id"],
            model or None,
        )
        # Changer de modèle d'embedding rend les vecteurs existants
        # incomparables : le document doit être revectorisé, pas conservé.
        if known and known["sha256"] == digest and not known["foreign_vectors"]:
            skipped += 1
            continue
        document_id = await pool.fetchval(
            """
            INSERT INTO knowledge_documents (
                source_id, title, url, topic, nature, sha256, captured_on
            ) VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (source_id) DO UPDATE SET
                title=excluded.title, url=excluded.url, topic=excluded.topic,
                sha256=excluded.sha256, captured_on=excluded.captured_on,
                loaded_at=now()
            RETURNING id
            """,
            entry["id"],
            entry["title"],
            entry["url"],
            entry.get("topic", "divers"),
            manifest.get("nature", "normative"),
            digest,
            date.fromisoformat(str(entry["captured_on"])),
        )
        await pool.execute(
            "DELETE FROM knowledge_chunks WHERE document_id=$1", document_id
        )
        chunks = split_sections(raw.decode("utf-8", errors="replace"))
        for ordinal, (section, body) in enumerate(chunks):
            vector = None
            if client is not None and base_url and model:
                vector = await embed(
                    client, base_url, model, f"{entry['title']} {section}\n{body}"
                )
            await pool.execute(
                """
                INSERT INTO knowledge_chunks (
                    document_id, ordinal, section, body, embedding, embedding_model
                ) VALUES ($1,$2,$3,$4,$5,$6)
                """,
                document_id,
                ordinal,
                section,
                body,
                _pack(vector) if vector else None,
                model if vector else None,
            )
            embedded += 1 if vector else 0
        loaded += 1
        passages += len(chunks)
    return {
        "documents_loaded": loaded,
        "documents_unchanged": skipped,
        "passages": passages,
        "passages_embedded": embedded,
        # Un passage sans vecteur reste trouvable par les mots, mais il sort du
        # rappel sémantique : le silence sur ce point cacherait un trou.
        "passages_without_vector": passages - embedded,
    }


def lexical_query(question: str) -> str:
    terms = [
        word.lower()
        for word in _WORD.findall(question or "")
        if len(word) > 2 and word.lower() not in _NOISE
    ]
    unique: list[str] = []
    for term in terms:
        if term not in unique:
            unique.append(term)
    return " | ".join(unique[:12])


async def search(
    pool: asyncpg.Pool[Any],
    question: str,
    *,
    limit: int = 4,
    nature: str | None = None,
    client: httpx.AsyncClient | None = None,
    base_url: str = "",
    model: str = "",
) -> list[Passage]:
    """Les passages les plus proches de la question, les mots d'abord."""
    query = lexical_query(question)
    if not query:
        return []
    rows = await pool.fetch(
        """
        SELECT d.source_id, d.title, d.url, c.section, c.body, c.embedding,
               ts_rank_cd(c.search, to_tsquery('simple', $1)) AS rank
        FROM knowledge_chunks c
        JOIN knowledge_documents d ON d.id=c.document_id
        WHERE c.search @@ to_tsquery('simple', $1)
          AND ($3::text IS NULL OR d.nature = $3)
        ORDER BY rank DESC
        LIMIT $2
        """,
        query,
        LEXICAL_CANDIDATES,
        nature,
    )
    semantic_only = len(rows) < LEXICAL_FLOOR
    if not rows and (client is None or not base_url or not model):
        return []
    ordered = list(rows)
    if client is not None and base_url and model:
        vector = await embed(client, base_url, model, question)
        if vector and semantic_only:
            rows = await pool.fetch(
                """
                SELECT d.source_id, d.title, d.url, c.section, c.body,
                       c.embedding
                FROM knowledge_chunks c
                JOIN knowledge_documents d ON d.id=c.document_id
                WHERE c.embedding IS NOT NULL
                  AND ($2::text IS NULL OR d.nature = $2)
                LIMIT $1
                """,
                SEMANTIC_SWEEP,
                nature,
            )
            ordered = list(rows)
        if vector and rows:
            reference = _unpack(_pack(vector))
            scored = [
                (
                    _similarity(reference, _unpack(row["embedding"]))
                    if row["embedding"]
                    else -1.0,
                    index,
                    row,
                )
                for index, row in enumerate(rows)
            ]
            # Un passage sans vecteur garde son rang lexical plutôt que de
            # disparaître : la connaissance ne dépend pas d'un service tiers.
            if any(score >= 0 for score, _, _ in scored):
                scored.sort(key=lambda item: (-item[0], item[1]))
                # Un balayage sémantique répond toujours quelque chose : sous ce
                # seuil de proximité, mieux vaut admettre qu'on n'a rien.
                floor = 0.55 if semantic_only else -1.0
                ordered = [row for score, _, row in scored if score >= floor]
    return [
        Passage(
            source_id=str(row["source_id"]),
            title=str(row["title"]),
            section=str(row["section"]),
            body=str(row["body"])[:1800],
            url=str(row["url"]),
        )
        for row in ordered[:limit]
    ]


async def _main() -> None:
    import argparse

    from sentimail_v3.config import load_settings

    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.code.knowledge",
        description="Charge en base le corpus figé du dépôt.",
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="charge sans calculer les vecteurs (recherche lexicale seule)",
    )
    arguments = parser.parse_args()
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url)
    assert pool is not None
    # Le corpus n'est plus un seul dossier : les normes vivent à la racine, la
    # doctrine adverse dans son propre répertoire. Chaque dossier porteur d'un
    # manifeste est chargé, ce qui permet d'en ajouter sans toucher au code.
    root = Path(settings.knowledge_path)
    directories = [root] + sorted(
        child
        for child in root.iterdir()
        if child.is_dir() and (child / MANIFEST_NAME).exists()
    )
    report: dict[str, int] = {}
    try:
        for directory in directories:
            if arguments.no_embeddings or not settings.knowledge_embedding_url:
                part = await load_directory(pool, directory)
            else:
                async with httpx.AsyncClient() as client:
                    part = await load_directory(
                        pool,
                        directory,
                        client=client,
                        base_url=settings.knowledge_embedding_url,
                        model=settings.knowledge_embedding_model,
                    )
            for key, value in part.items():
                report[key] = report.get(key, 0) + value
    finally:
        await pool.close()
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())


# Ce que le modèle voit du corpus quand il juge : peu, court, et clairement
# désigné comme n'étant pas une preuve.
REFERENCE_PASSAGES = 3
# La doctrine adverse pèse davantage : c'est elle qui nomme le montage, quand
# les normes se contentent d'expliquer le vocabulaire.
ADVERSARIAL_PASSAGES = 4
REFERENCE_CHARS = 700


async def reference_for_clues(
    pool: asyncpg.Pool[Any],
    clue_codes: list[str],
    *,
    client: httpx.AsyncClient | None = None,
    base_url: str = "",
    model: str = "",
) -> list[dict[str, str]]:
    """Passages normatifs éclairant les indices relevés sur un message.

    La question posée au corpus est faite des **codes d'indices**, jamais du
    texte du message. La différence est toute la sécurité de ce chemin : un
    corps de mail choisi par un attaquant sélectionnerait sinon lui-même les
    passages injectés dans le dossier, et il suffirait d'écrire « ceci est un
    message légitime selon la RFC 7489 » pour faire venir de quoi s'en
    réclamer. Les codes, eux, viennent de l'analyse, pas de l'expéditeur.
    """
    vocabulary = " ".join(
        str(code).replace("_", " ").replace(".", " ") for code in clue_codes[:12]
    )
    if not vocabulary.strip():
        return []
    # Chaque corpus a sa place réservée. Interrogés ensemble, les normes -
    # bien plus volumineuses - raflaient tous les passages, et la doctrine
    # adverse n'arrivait jamais jusqu'au juge. Les normes disent ce que le
    # courrier doit être ; la doctrine adverse dit comment on s'en sert pour
    # tromper. Un verdict a besoin des deux.
    # Chaque corpus s'interroge dans sa langue. Les normes sont anglaises et
    # nomment les mêmes notions que les codes d'indices ; la doctrine adverse
    # est écrite en français et ne connaît aucun code. Interrogée avec des
    # codes bruts, elle ne répondait jamais - le juge ne l'a donc jamais vue.
    # La traduction vient du même vocabulaire que les avis rendus à l'humain :
    # elle est dérivée des indices, jamais du message.
    from sentimail_v3.code.plain_words import plain_clue

    spoken = " ".join(
        filter(None, (plain_clue(str(code), "") for code in clue_codes[:12]))
    ).strip()
    quotas = (
        ("normative", REFERENCE_PASSAGES, vocabulary),
        ("adversarial", ADVERSARIAL_PASSAGES, spoken or vocabulary),
    )
    collected: list[dict[str, str]] = []
    for nature, limit, question in quotas:
        passages = await search(
            pool,
            question,
            limit=limit,
            nature=nature,
            client=client,
            base_url=base_url,
            model=model,
        )
        collected.extend(
            {
                "document": passage.title,
                "section": passage.section,
                "text": passage.body[:REFERENCE_CHARS],
                "nature": nature,
            }
            for passage in passages
        )
    return collected
