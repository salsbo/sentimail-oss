"""Preuve de maîtrise d'un domaine, avant qu'il ne soit protégé.

Protéger un domaine, c'est intercepter son courrier : le demander ne suffit pas,
il faut le prouver. La preuve retenue est un enregistrement TXT sur
`_sentimail.<fqdn>`, parce que seul celui qui tient la zone peut l'y écrire.

La vérification ne fait qu'une chose : elle constate. Elle inscrit `verified_at`
quand la preuve est là, et **jamais** ne passe le domaine en `active`. Ouvrir la
protection reste une décision humaine, prise après la preuve technique : un
domaine peut être vérifié et refusé (facturation absente, périmètre discuté,
contact non identifié), et cette séparation garde ce refus possible.

Tout est fail-soft : une panne DNS ne fait pas échouer l'enrôlement, elle produit
un résultat qui dit « je n'ai pas pu voir », distinct de « ce n'est pas publié ».
Confondre les deux ferait conclure à une fraude sur une simple coupure réseau.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import asyncpg
import dns.asyncresolver
import dns.resolver

from sentimail_v3.config import load_settings
from sentimail_v3.code.reference import nommer_dossier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-enrolment")

# Le sous-domaine réservé : un nom qui commence par un tiret bas ne peut pas être
# celui d'un service, donc la preuve ne consomme rien dans la zone du client.
TXT_LABEL = "_sentimail"

# Les interfaces DNS grand public ajoutent souvent une étiquette devant la valeur
# collée ; on l'accepte plutôt que de rejeter une publication de bonne foi.
TOKEN_PREFIXES = ("sentimail-verification=", "sentimail=")

# Constats possibles. Ils sont distincts parce qu'ils appellent des suites
# différentes : corriger la zone, attendre, ou rappeler l'administrateur.
VERIFIED = "verified"
UNKNOWN_DOMAIN = "unknown_domain"
NXDOMAIN = "nxdomain"
TOKEN_ABSENT = "token_absent"
TOKEN_MISMATCH = "token_mismatch"
RESOLUTION_FAILED = "resolution_failed"

_DETAILS = {
    VERIFIED: "Le jeton publié correspond : la maîtrise du domaine est prouvée.",
    UNKNOWN_DOMAIN: "Domaine absent de la table domains : rien à vérifier.",
    NXDOMAIN: "Aucun enregistrement à ce nom : le TXT n'a pas encore été publié.",
    TOKEN_ABSENT: "Le nom existe mais ne porte aucune valeur TXT exploitable.",
    TOKEN_MISMATCH: "Une valeur est publiée, mais ce n'est pas le jeton attendu.",
    RESOLUTION_FAILED: "Résolution DNS impossible : constat impossible, pas un refus.",
}

# Une réponse TXT légitime tient en quelques valeurs ; au-delà, on ne garde que
# de quoi diagnostiquer, pour ne pas gonfler l'audit avec une zone bavarde.
MAX_RECORDED_VALUES = 5
MAX_RECORDED_LENGTH = 128

TxtResolver = Callable[[str], Awaitable[tuple[str, list[str]]]]


@dataclass(frozen=True)
class VerificationResult:
    """Ce qui a été constaté, et ce que cela autorise."""

    fqdn: str
    outcome: str
    detail: str
    status: str | None = None
    published: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.outcome == VERIFIED

    def as_payload(self) -> dict[str, object]:
        return {
            "fqdn": self.fqdn,
            "outcome": self.outcome,
            "status": self.status,
            "record": f"{TXT_LABEL}.{self.fqdn}",
            "published": self.published,
        }


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


def normalize_fqdn(value: object) -> str:
    """Un nom de domaine se compare en minuscules, sans point final ni espace."""
    return str(value or "").strip().strip(".").casefold()


def _txt_value(answer: object) -> str:
    """Une valeur TXT peut arriver découpée en tronçons : elle se relit d'un bloc.

    Un jeton de 32 caractères tient dans un tronçon, mais un panneau DNS peut le
    republier autrement ; recoller évite un faux « jeton différent ».
    """
    chunks = getattr(answer, "strings", None)
    if chunks:
        return "".join(
            chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
            for chunk in chunks
        )
    return str(getattr(answer, "to_text", lambda: answer)()).strip('"')


def _strip_prefix(value: str) -> str:
    cleaned = value.strip().strip('"').strip()
    for prefix in TOKEN_PREFIXES:
        if cleaned.casefold().startswith(prefix):
            return cleaned[len(prefix) :].strip()
    return cleaned


def matches_token(published: list[str], token: str) -> bool:
    expected = str(token or "").strip().casefold()
    if not expected:
        return False
    return any(_strip_prefix(value).casefold() == expected for value in published)


async def resolve_txt(name: str) -> tuple[str, list[str]]:
    """Lit les valeurs TXT d'un nom, en nommant la raison d'un échec.

    Les mêmes garde-fous que l'enrichissement : temps court, aucune exception ne
    remonte, et la nature de la panne est conservée pour le rapport.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        answers = await resolver.resolve(name, "TXT")
    except dns.resolver.NXDOMAIN:
        return (NXDOMAIN, [])
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return (TOKEN_ABSENT, [])
    except Exception as exc:  # noqa: BLE001 - une panne DNS n'est pas un refus
        return (f"{RESOLUTION_FAILED}:{type(exc).__name__}", [])
    return ("ok", [_txt_value(answer) for answer in answers])


async def load_domain(pool: asyncpg.Pool[Any], fqdn: str) -> asyncpg.Record | None:
    return await pool.fetchrow(
        """
        SELECT id::text, fqdn, status, verification_token, verified_at
        FROM domains WHERE lower(fqdn)=$1
        """,
        normalize_fqdn(fqdn),
    )


async def _record(
    pool: asyncpg.Pool[Any], result: VerificationResult, actor: str
) -> None:
    """Chaque tentative est tracée, réussie ou non.

    Un enrôlement est un changement de périmètre de surveillance : la trace des
    essais infructueux vaut autant que celle du succès, car elle documente qui a
    demandé quoi, et depuis quand.
    """
    action = "domain.verified" if result.verified else "domain.verification_failed"
    await pool.execute(
        "INSERT INTO audit_log(actor,action,payload) VALUES ($1,$2,$3::jsonb)",
        actor,
        action,
        _json(result.as_payload()),
    )


async def verify_domain(
    pool: asyncpg.Pool[Any],
    fqdn: str,
    *,
    resolver: TxtResolver | None = None,
    actor: str = "operator",
) -> VerificationResult:
    """Constate la preuve de maîtrise d'un domaine et l'inscrit si elle est là.

    Ne modifie jamais `status` : la vérification est un fait, l'activation une
    décision. Le résolveur est injectable pour que les tests n'aient pas besoin
    du réseau.
    """
    name = normalize_fqdn(fqdn)
    domain = await load_domain(pool, name)
    if domain is None:
        result = VerificationResult(name, UNKNOWN_DOMAIN, _DETAILS[UNKNOWN_DOMAIN])
        await _record(pool, result, actor)
        _log("domain.verification", fqdn=name, outcome=result.outcome)
        return result

    status, values = await (resolver or resolve_txt)(f"{TXT_LABEL}.{name}")
    published = [value[:MAX_RECORDED_LENGTH] for value in values[:MAX_RECORDED_VALUES]]
    if status.startswith(RESOLUTION_FAILED):
        outcome = RESOLUTION_FAILED
        detail = f"{_DETAILS[RESOLUTION_FAILED]} ({status.split(':', 1)[-1]})"
    elif status in {NXDOMAIN, TOKEN_ABSENT}:
        outcome, detail = status, _DETAILS[status]
    elif not values:
        outcome, detail = TOKEN_ABSENT, _DETAILS[TOKEN_ABSENT]
    elif matches_token(values, str(domain["verification_token"])):
        outcome, detail = VERIFIED, _DETAILS[VERIFIED]
    else:
        outcome, detail = TOKEN_MISMATCH, _DETAILS[TOKEN_MISMATCH]

    if outcome == VERIFIED:
        # Idempotent : revérifier un domaine déjà prouvé rafraîchit la date, ce
        # qui documente que la preuve tient encore aujourd'hui.
        await pool.execute(
            "UPDATE domains SET verified_at=now(), updated_at=now() WHERE id=$1::uuid",
            domain["id"],
        )

    result = VerificationResult(
        fqdn=name,
        outcome=outcome,
        detail=detail,
        status=str(domain["status"]),
        published=published,
    )
    await _record(pool, result, actor)
    _log("domain.verification", fqdn=name, outcome=outcome, status=result.status)
    return result


def summarize(result: VerificationResult, token: str | None) -> str:
    lines = [
        f"Domaine : {result.fqdn}",
        f"Constat : {result.outcome}",
        f"          {result.detail}",
    ]
    if result.status is not None:
        lines.append(f"Etat    : {result.status}")
    if result.published:
        lines.append("Publie  : " + ", ".join(result.published))
    if result.verified:
        lines.append(
            "\nPreuve enregistree. L'activation reste manuelle :\n"
            "  UPDATE domains SET status='active' WHERE fqdn='" + result.fqdn + "';"
        )
    elif token:
        lines.append(
            f'\nA publier dans la zone :\n  {TXT_LABEL}.{result.fqdn}. IN TXT "{token}"'
        )
    elif result.outcome == UNKNOWN_DOMAIN:
        lines.append(
            "\nCreer d'abord la ligne :\n"
            "  INSERT INTO domains (fqdn, admin_email) VALUES ('"
            + result.fqdn
            + "', '<contact>');"
        )
    return "\n".join(lines)


async def run(fqdn: str, *, show_token: bool) -> int:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        result = await verify_domain(pool, fqdn)
        token = None
        if show_token and result.outcome != UNKNOWN_DOMAIN:
            domain = await load_domain(pool, fqdn)
            token = str(domain["verification_token"]) if domain else None
        print(summarize(result, token))
        return 0 if result.verified else 1
    finally:
        await pool.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.code.enrolment",
        description=(
            "Verifie qu'un domaine prouve sa maitrise via le TXT "
            f"{TXT_LABEL}.<fqdn>. La verification n'active jamais le domaine : "
            "elle constate, l'ouverture reste une decision humaine."
        ),
    )
    parser.add_argument("fqdn", help="domaine a verifier, par exemple exemple.fr")
    parser.add_argument(
        "--no-token",
        action="store_true",
        help="n'affiche pas l'enregistrement TXT a publier en cas d'echec",
    )
    arguments = parser.parse_args()
    raise SystemExit(
        asyncio.run(run(arguments.fqdn, show_token=not arguments.no_token))
    )


if __name__ == "__main__":
    main()
