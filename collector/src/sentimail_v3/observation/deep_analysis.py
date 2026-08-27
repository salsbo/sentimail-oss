from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import statistics
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import asyncpg
import httpx
import tldextract

from sentimail_v3.code.attachment_facts import attachment_clues
from sentimail_v3.code.correlation import correlations
from sentimail_v3.execution.campaign_memory import match_campaign
from sentimail_v3.observation.parser import parse_message
from sentimail_v3.llm import provider_chat_json
from types import SimpleNamespace

from sentimail_v3.observation.deep_hooks import DEEP_HOOKS, run_deep_hooks
from sentimail_v3.code.activity_coherence import (
    COHERENCE_PROMPT,
    coherence_clue,
    coherence_question,
    should_ask,
)
from sentimail_v3.code.sender_site import (
    activity_registers,
    is_interstitial,
)
from sentimail_v3.code.organisation import (
    nameserver_signature,
    organisation_signature,
    same_organisation_destinations,
)
from sentimail_v3.config import Settings
from sentimail_v3.crypto import load_key, reveal
from sentimail_v3.code.reference import nommer_dossier

_LOGGER = logging.getLogger("sentimail-v3-deep-analysis")


def _log(event: str, **fields: object) -> None:
    """Journalise un fait de l'analyse profonde.

    Trois appels existaient déjà - deux pannes de modèle et un constat effacé -
    sans que la fonction soit définie nulle part : chacun aurait levé une
    `NameError` au moment précis où l'inspection devait rester silencieuse et
    fail-soft. Le nom manquant transformait une panne bénigne en enquêteur en
    erreur.
    """
    _LOGGER.info(
        json.dumps(
            {"event": event, **nommer_dossier(dict(fields))},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    )

BASE_URLS = 20
MAX_URLS = 40
URLS_PER_APEX = 2
# Délais du sandbox : ils décrivent le réseau, pas la destination. Ils méritent
# une seconde tentative avant d'être retenus comme une inspection manquante.
TRANSIENT_URL_ERRORS = frozenset({"hop_timeout", "sandbox_total_timeout"})
MAX_ATTACHMENTS = 10
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
# En deçà de cet âge, une destination inter-apex reste suspecte même sous
# authentification : les newsletters légitimes renvoient vers des apex établis,
# pas vers un domaine enregistré la veille.
FRESH_DESTINATION_DAYS = 30
_extract = tldextract.TLDExtract(suffix_list_urls=())
_SINGLE_USE_PATH = re.compile(
    r"(?:^|[/_.-])(otp|one[-_]?time|magic[-_]?link|verify|verification|confirm|"
    r"confirmation|activate|activation|reset|recover|unsubscribe|oneclick|callback)(?:$|[/_.-])",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_KEYS = {
    "code", "key", "nonce", "otp", "password_reset", "reset_token", "ticket",
    "token", "unsubscribe", "verification", "verify",
}
_TEXT_URL = re.compile(r"https?://[^\s<>'\"\)]+", re.IGNORECASE)
_VISIBLE_DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", re.IGNORECASE)
_SECONDARY_LINK_TEXT = re.compile(
    r"\b(facebook|instagram|linkedin|youtube|tiktok|twitter|app store|"
    r"google play|mentions l[ée]gales|politique de confidentialit[ée]|privacy)\b",
    re.IGNORECASE,
)
_SIDE_EFFECT_LINK_TEXT = re.compile(
    r"\b(d[ée]sabonn(?:er|ement|ez|e|[ée])?|unsubscribe|"
    r"g[ée]rer (?:mes |vos )?pr[ée]f[ée]rences|"
    r"email preferences|opt[- ]?out)\b",
    re.IGNORECASE,
)
_PRIMARY_ACTION_LINK_TEXT = re.compile(
    r"\b(connexion|connecter|login|sign[ -]?in|v[ée]rifier|verify|confirmer|confirm|"
    r"activer|activate|payer|pay|r[ée]gler|facture|invoice|t[ée]l[ée]charger|download|"
    r"ouvrir|open|voir|view|continuer|continue|r[ée]initialiser|reset)\b",
    re.IGNORECASE,
)
_GENERIC_LINK_LABEL = re.compile(
    r"^(?:read more|learn more|click here|en savoir plus|lire la suite|voir|ouvrir|open|view)$",
    re.IGNORECASE,
)


class _HtmlDestinations(HTMLParser):
    """Sépare les destinations activables des simples ressources de rendu."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str, str]] = []
        self.forms: list[str] = []
        self.resources: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._footer_depth = 0
        self._link_context = "primary"

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        lowered = tag.casefold()
        values = {name.casefold(): value for name, value in attrs if value}
        if lowered == "footer":
            self._footer_depth += 1
        if lowered == "a" and values.get("href"):
            self._href = values["href"]
            self._text = []
            self._link_context = "footer" if self._footer_depth else "primary"
        elif lowered == "img" and self._href is not None and values.get("alt"):
            self._text.append(values["alt"])
        elif lowered == "form" and values.get("action"):
            self.forms.append(values["action"])
        elif lowered in {"img", "source", "video"}:
            resource = values.get("src") or values.get("poster")
            if resource:
                self.resources.append(resource)

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            visible = " ".join(self._text).strip()
            context = (
                "secondary_navigation"
                if _SECONDARY_LINK_TEXT.search(visible)
                else self._link_context
            )
            self.links.append((self._href, visible, context))
            self._href = None
            self._text = []
            self._link_context = "primary"
        if tag.casefold() == "footer":
            self._footer_depth = max(0, self._footer_depth - 1)


def _json(value: object) -> str:
    return json.dumps(
        _postgres_json_safe(value),
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def _postgres_json_safe(value: object) -> object:
    """Retire les caractères que PostgreSQL JSONB refuse de stocker.

    JSON autorise ``\u0000`` mais PostgreSQL interdit ce caractère dans une
    valeur ``jsonb``. Les extracteurs PDF/OCR peuvent légitimement en produire.
    Le remplacement est fait à la frontière de persistance, récursivement, afin
    qu'une erreur de stockage ne soit jamais requalifiée en échec d'analyse.
    """
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, list):
        return [_postgres_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_postgres_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {
            (
                key.replace("\x00", "\ufffd")
                if isinstance(key, str)
                else key
            ): _postgres_json_safe(item)
            for key, item in value.items()
        }
    return value


def _json_object(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        decoded = json.loads(value)
        if isinstance(decoded, dict):
            return decoded
    raise TypeError("cached analysis result is not a JSON object")


def _apex(domain: str) -> str:
    parsed = _extract(domain.casefold().rstrip("."))
    return ".".join(part for part in (parsed.domain, parsed.suffix) if part)


def _explained_authenticated_redirect_limit(
    data: dict[str, object], authenticated: bool
) -> bool:
    """Reconnaît une limite de navigation confinée à une destination stable.

    Un prestataire de suivi peut rediriger vers un portail authentique qui
    boucle ensuite dans une salle d'attente ou un parcours de connexion. La
    limite du sandbox n'est pas une preuve manquante matérielle si la chaîne
    HTTPS n'effectue qu'une transition d'apex, reste ensuite sur l'apex final
    et répète un point de navigation : le sandbox a observé une boucle, pas une
    destination ultérieure inconnue.
    """
    if not authenticated or data.get("error") != "too_many_redirects":
        return False
    chain = data.get("chain")
    if not isinstance(chain, list) or not chain:
        return False

    urls = [str(data.get("initial_url") or "")]
    for item in chain:
        if not isinstance(item, dict) or not item.get("url"):
            return False
        urls.append(str(item["url"]))

    apexes: list[str] = []
    endpoints: list[tuple[str, str]] = []
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() != "https" or not parsed.hostname:
            return False
        apex = _apex(parsed.hostname)
        if not apex:
            return False
        if not apexes or apexes[-1] != apex:
            apexes.append(apex)
        endpoints.append((apex, f"{parsed.hostname.casefold()}{parsed.path}"))

    final_apex = str(data.get("final_apex") or "")
    if not final_apex and data.get("final_host"):
        final_apex = _apex(str(data["final_host"]))
    final_endpoints = [endpoint for apex, endpoint in endpoints if apex == final_apex]
    observed_cycle = len(set(final_endpoints)) < len(final_endpoints)
    return bool(
        final_apex
        and len(apexes) <= 2
        and apexes[-1] == final_apex
        and observed_cycle
    )


def is_navigation_failure(error: object) -> bool:
    """Distingue une panne de navigation d'un signal défavorable observé.

    Un délai dépassé pendant la navigation décrit l'état du réseau, pas le
    contenu de la destination. Il appartient donc à la même famille que les
    erreurs de fetch, quelle que soit l'étape de la chaîne où il survient. Une
    panne de notre propre sandbox n'en fait pas partie : elle reste une
    inspection manquante.
    """
    value = str(error or "")
    return value.startswith(("fetch_error:", "timeout:")) or value in TRANSIENT_URL_ERRORS


def _explained_authenticated_same_apex_fetch_error(
    data: dict[str, object], authenticated: bool
) -> bool:
    """Une panne HTTP même-apex authentifiée est une limite, pas un danger absent."""
    initial_url = str(data.get("initial_url") or "")
    initial_apex = str(data.get("initial_apex") or "")
    final_apex = str(data.get("final_apex") or "")
    return bool(
        authenticated
        and is_navigation_failure(data.get("error"))
        and initial_url.casefold().startswith("https://")
        and initial_apex
        and initial_apex == final_apex
    )


def _bounded(value: object, *, depth: int = 0) -> object:
    if depth >= 4:
        return "[depth-limited]"
    if isinstance(value, str):
        return value[:1500]
    if isinstance(value, list):
        return [_bounded(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _bounded(item, depth=depth + 1)
            for key, item in list(value.items())[:40]
        }
    return value


def _url_summary(
    data: dict[str, object],
    key: str,
    candidate: dict[str, str] | None = None,
) -> dict[str, object]:
    forms = data.get("forms")
    visible_links = data.get("visible_links")
    comparaison = data.get("profile_comparison")
    initial_apex = str(data.get("initial_apex") or "")
    final_apex = str(data.get("final_apex") or "")
    return {
        "url_hash": key,
        "role": (candidate or {}).get("role"),
        "link_context": (candidate or {}).get("link_context"),
        "visible_text": (candidate or {}).get("visible_text"),
        "displayed_apex": (candidate or {}).get("displayed_apex"),
        "initial_url": str(data.get("initial_url") or "")[:2048],
        "initial_host": data.get("initial_host"),
        "initial_apex": data.get("initial_apex"),
        "final_host": data.get("final_host"),
        "final_apex": data.get("final_apex"),
        "final_status": data.get("final_status"),
        # Le sandbox historique appelle "cloaking" tout changement d'apex.
        # On conserve le fait sous son vrai nom : une redirection ne démontre
        # ni dissimulation conditionnelle, ni intention malveillante.
        "cross_apex_redirect": bool(
            initial_apex and final_apex and initial_apex != final_apex
        ),
        "sandbox_cross_apex_flag": bool(data.get("cloaking")),
        # Le service conditionnel, lui, est établi : le même lien a été demandé
        # sous deux identités et les réponses divergent structurellement. Le
        # dire même quand la réponse est non permet à l'examen de distinguer
        # « pas de cloaking » de « pas cherché ».
        "profiles_compared": bool(
            isinstance(comparaison, dict)
            and not comparaison.get("comparison_incomplete")
        ),
        "cloaking_detected": bool(
            isinstance(comparaison, dict) and comparaison.get("cloaking_detected")
        ),
        "cloaking_divergences": list(
            (comparaison or {}).get("divergences") or []
        ) if isinstance(comparaison, dict) else [],
        "cloaking_evidence": _bounded(
            (comparaison or {}).get("evidence") if isinstance(comparaison, dict) else None
        ),
        "same_apex_redirect": data.get("same_apex_redirect"),
        "form_count": len(forms) if isinstance(forms, list) else int(bool(forms)),
        "forms": _bounded(forms),
        "redirect_chain": _bounded(data.get("chain")),
        "network_hops": _bounded(data.get("hops")),
        "qr_codes": _bounded(data.get("qr_codes")),
        "visible_link_count": (
            len(visible_links) if isinstance(visible_links, list) else 0
        ),
        "body_excerpt": str(data.get("body_excerpt") or "")[:1500],
        "error": _bounded(data.get("error")),
        "navigation_limit_explained": bool(
            data.get("navigation_limit_explained")
        ),
        "navigation_limit_reason": data.get("navigation_limit_reason"),
        "analysis_incomplete": bool(data.get("analysis_incomplete")),
        "analysis_skipped": bool(data.get("analysis_skipped")),
        "skip_reason": data.get("skip_reason"),
    }


def _decoded_part_text(part: EmailMessage) -> str:
    try:
        value = part.get_content()
        if isinstance(value, str):
            return value
    except Exception:  # noqa: BLE001 - MIME exotique, extraction fail-soft
        pass
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _message_url_candidates(raw: bytes) -> tuple[list[dict[str, str]], int]:
    """Priorise ce que l'utilisateur peut ouvrir, puis les images à inspecter.

    Les DTD, namespaces, CSS et pixels ne rendent plus une preuve incomplète.
    Les ressources de rendu peuvent encore être inspectées pour les QR codes si
    le budget restant le permet.
    """
    root: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    actionable: list[dict[str, str]] = []
    resources: list[dict[str, str]] = []

    def add(
        target: list[dict[str, str]],
        url: str,
        role: str,
        visible: str = "",
        link_context: str = "primary",
    ) -> None:
        value = url.strip().rstrip(".,;:!?")
        if not value.casefold().startswith(("http://", "https://")):
            return
        try:
            if not urlsplit(value).hostname:
                return
        except ValueError:
            return
        displayed = _VISIBLE_DOMAIN.search(visible)
        target.append(
            {
                "url": value,
                "role": role,
                "displayed_apex": _apex(displayed.group(0)) if displayed else "",
                "visible_text": " ".join(visible.split())[:240],
                "link_context": link_context,
            }
        )

    for part in root.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        value = _decoded_part_text(part)
        if content_type == "text/plain":
            for match in _TEXT_URL.finditer(value[:1_000_000]):
                add(
                    actionable,
                    match.group(0),
                    "plain_text",
                    _plain_link_label(value, match.start()),
                )
            continue
        parser = _HtmlDestinations()
        try:
            parser.feed(value[:2_000_000])
        except Exception:  # noqa: BLE001 - HTML malformé, analyse fail-soft
            continue
        for href, visible, link_context in parser.links:
            add(actionable, href, "html_link", visible, link_context)
        for action in parser.forms:
            add(actionable, action, "html_form")
        for resource in parser.resources:
            add(resources, resource, "render_resource")

    unique_actionable: list[dict[str, str]] = []
    positions: dict[str, int] = {}
    priority = {"plain_text": 1, "html_link": 2, "html_form": 3}
    for candidate in actionable:
        existing_position = positions.get(candidate["url"])
        if existing_position is not None:
            existing = unique_actionable[existing_position]
            if priority.get(candidate["role"], 0) > priority.get(existing["role"], 0):
                unique_actionable[existing_position] = candidate
            continue
        positions[candidate["url"]] = len(unique_actionable)
        unique_actionable.append(candidate)
    resource_total = 0
    unique_resources: list[dict[str, str]] = []
    for candidate in resources:
        if candidate["url"] in positions:
            continue
        resource_total += 1
        positions[candidate["url"]] = len(positions)
        unique_resources.append(candidate)
    return unique_actionable + unique_resources, resource_total


def _plain_link_label(value: str, start: int) -> str:
    """Associe une URL texte à son libellé voisin sans conserver son secret.

    Les alternatives texte écrivent souvent ``Download invoice (https://...)``.
    Conserver les quelques mots précédents permet de rapprocher cette variante
    de l'ancre HTML équivalente, sans exposer le chemin ou les paramètres URL.
    """
    before = value[max(0, start - 180) : start]
    before = _TEXT_URL.sub(" ", before)
    segment = re.split(r"[\r\n\]\)>]+", before)[-1]
    words = re.findall(r"[^\s\[\](){}<>]+", segment)
    return " ".join(words[-6:])[:160]


def _normalized_link_label(value: object) -> str:
    label = " ".join(str(value or "").casefold().split())
    return re.sub(r"[^\w]+", " ", label, flags=re.UNICODE).strip()


def _contextualize_equivalent_url_limits(
    results: list[dict[str, object]], authenticated: bool
) -> None:
    """Explique une panne sur une variante MIME couverte par son équivalent.

    Une alternative texte et une alternative HTML peuvent représenter le même
    bouton avec deux URL différentes (lien direct et lien de suivi). La panne
    d'une variante n'est pas une lacune supplémentaire lorsque : le libellé est
    identique, les deux URL restent sur le même apex HTTPS et l'autre variante
    a été inspectée ou possède déjà une limite même-apex expliquée. Une variante
    vers un autre apex reste toujours à inspecter.
    """
    if not authenticated:
        return
    for value in results:
        if not value.get("error") or value.get("navigation_limit_explained"):
            continue
        label = _normalized_link_label(value.get("visible_text"))
        initial_apex = str(value.get("initial_apex") or "")
        initial_url = str(value.get("initial_url") or "")
        if not label or not initial_apex or not initial_url.casefold().startswith("https://"):
            continue
        for other in results:
            if other is value or _normalized_link_label(other.get("visible_text")) != label:
                continue
            if str(other.get("initial_apex") or "") != initial_apex:
                continue
            if str(other.get("final_apex") or "") != initial_apex:
                continue
            if other.get("analysis_incomplete"):
                continue
            if other.get("error") and not other.get("navigation_limit_explained"):
                continue
            value["navigation_limit_explained"] = True
            value["navigation_limit_reason"] = (
                "authenticated_equivalent_mime_link_same_apex"
            )
            break


def is_single_use_or_side_effect_url(url: str) -> bool:
    """Détecte les URL qu'un GET de sécurité pourrait consommer ou déclencher."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    path = parsed.path.casefold()
    if "/cdn-cgi/access/" in path or _SINGLE_USE_PATH.search(path):
        return True
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized = key.casefold().replace("-", "_")
        if normalized in _SENSITIVE_QUERY_KEYS and len(value) >= 6:
            return True
    return False


async def _message_is_dmarc_aligned(
    pool: asyncpg.Pool[Any], message_id: str
) -> bool:
    return bool(
        await pool.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid AND c.clue_code='AUTH_DMARC_PASS'
            )
            """,
            message_id,
        )
    )


def _attachment_summary(data: dict[str, object]) -> dict[str, object]:
    preferred = {
        "path", "filename", "content_type", "mime", "sha256", "score", "verdict",
        "findings", "yara", "macros", "archive", "pdf", "ocr",
        "analysis_incomplete", "reason", "error",
    }
    return {
        str(key): _bounded(value)
        for key, value in data.items()
        if str(key) in preferred
    }


def _part_payloads(raw: bytes) -> dict[str, tuple[str, str, bytes]]:
    root: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    result: dict[str, tuple[str, str, bytes]] = {}

    def visit(part: EmailMessage, path: str) -> None:
        if part.is_multipart():
            for index, child in enumerate(part.iter_parts()):
                visit(child, f"{path}.{index}")
            return
        if part.get_content_disposition() == "attachment" or part.get_filename():
            payload = part.get_payload(decode=True)
            result[path] = (
                str(part.get_filename() or f"attachment-{path}"),
                part.get_content_type(),
                payload if isinstance(payload, bytes) else b"",
            )

    visit(root, "0")
    return result


async def _save_analysis(
    pool: asyncpg.Pool[Any],
    message_id: str,
    kind: str,
    key: str,
    source: str,
    status: str,
    result: dict[str, object],
    error: Exception | None = None,
    started_at: datetime | None = None,
) -> None:
    """Enregistre une inspection, et le temps qu'elle a réellement coûté.

    Les deux bornes étaient posées à l'écriture, donc identiques : la durée
    valait zéro sur 3641 inspections sur 3704. Une fermeture TLS de trente
    secondes par URL a pu passer des semaines sans laisser de trace, faute de
    la seule mesure qui l'aurait montrée.
    """
    debut = started_at or datetime.now(timezone.utc)
    await pool.execute(
        """
        INSERT INTO external_analyses (
            message_id, subject_kind, subject_key, source, status, result,
            error_type, error_detail, started_at, completed_at
        ) VALUES ($1::uuid,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,now())
        ON CONFLICT (message_id, subject_kind, subject_key, source) DO UPDATE SET
            status=EXCLUDED.status, result=EXCLUDED.result,
            error_type=EXCLUDED.error_type, error_detail=EXCLUDED.error_detail,
            started_at=EXCLUDED.started_at,
            completed_at=now()
        """,
        message_id,
        kind,
        key,
        source,
        status,
        _json(result),
        type(error).__name__ if error else None,
        str(error)[:500] if error else None,
        debut,
    )


def _candidate_apex(candidate: dict[str, str]) -> str:
    try:
        return _apex(urlsplit(candidate["url"]).hostname or "")
    except (KeyError, ValueError):
        return ""


def _candidate_group_key(candidate: dict[str, str]) -> tuple[str, str, str]:
    """Regroupe les variantes équivalentes sans fusionner des liens ambigus.

    Un libellé descriptif identique sur le même apex représente généralement la
    même action dans les alternatives texte et HTML. Les libellés génériques
    comme « lire la suite » conservent le chemin afin que deux articles distincts
    ne soient jamais assimilés.
    """
    apex = _candidate_apex(candidate)
    label = _normalized_link_label(candidate.get("visible_text"))
    try:
        path = urlsplit(candidate["url"]).path.casefold().rstrip("/") or "/"
    except (KeyError, ValueError):
        path = candidate.get("url", "")[:500]
    identity = label if label and not _GENERIC_LINK_LABEL.fullmatch(label) else path
    return apex, candidate.get("link_context", "primary"), identity[:500]


def _representative_candidates(
    candidates: list[dict[str, str]],
) -> list[dict[str, str]]:
    representatives: list[dict[str, str]] = []
    positions: dict[tuple[str, str, str], int] = {}
    role_priority = {
        "render_resource": 0,
        "plain_text": 1,
        "html_link": 2,
        "html_form": 3,
    }
    for candidate in candidates:
        key = _candidate_group_key(candidate)
        position = positions.get(key)
        if position is None:
            positions[key] = len(representatives)
            representatives.append(candidate)
            continue
        existing = representatives[position]
        if role_priority.get(candidate.get("role", ""), 0) > role_priority.get(
            existing.get("role", ""), 0
        ):
            representatives[position] = candidate
    return representatives


def _candidate_priority(candidate: dict[str, str]) -> tuple[int, int]:
    if candidate.get("role") == "html_form":
        return 0, 0
    if _PRIMARY_ACTION_LINK_TEXT.search(candidate.get("visible_text", "")):
        return 0, 1
    if candidate.get("link_context") == "primary":
        return 1, 0
    if candidate.get("link_context") == "footer":
        return 2, 0
    if candidate.get("link_context") == "secondary_navigation":
        return 3, 0
    return 4, 0


def _diverse_order(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    """Échantillonne d'abord chaque apex, puis approfondit chaque destination."""
    buckets: dict[str, list[dict[str, str]]] = {}
    for candidate in sorted(candidates, key=_candidate_priority):
        buckets.setdefault(_candidate_apex(candidate), []).append(candidate)
    ordered: list[dict[str, str]] = []
    while any(buckets.values()):
        for bucket in buckets.values():
            if bucket:
                ordered.append(bucket.pop(0))
    return ordered


def _select_url_candidates(
    candidates: list[dict[str, str]],
) -> tuple[list[dict[str, str]], dict[str, object]]:
    actionable = [value for value in candidates if value["role"] != "render_resource"]
    resources = [value for value in candidates if value["role"] == "render_resource"]
    representatives = _representative_candidates(actionable)
    primary = [
        value
        for value in representatives
        if value.get("link_context") not in {"footer", "secondary_navigation"}
    ]
    secondary = [
        value
        for value in representatives
        if value.get("link_context") in {"footer", "secondary_navigation"}
    ]
    actionable_apexes = {_candidate_apex(value) for value in representatives}
    actionable_apexes.discard("")
    adaptive_budget = min(
        MAX_URLS,
        max(BASE_URLS, len(actionable_apexes) * URLS_PER_APEX),
    )
    ordered = _diverse_order(primary) + _diverse_order(secondary)
    selected = ordered[:adaptive_budget]
    if len(selected) < adaptive_budget:
        selected.extend(resources[: adaptive_budget - len(selected)])
    selected_actionable = [
        value for value in selected if value.get("role") != "render_resource"
    ]
    selected_apexes = {_candidate_apex(value) for value in selected_actionable}
    selected_apexes.discard("")
    coverage: dict[str, object] = {
        "strategy": "adaptive-contextual-representatives-v1",
        "base_budget": BASE_URLS,
        "hard_budget": MAX_URLS,
        "adaptive_budget": adaptive_budget,
        "actionable_total": len(actionable),
        "actionable_representatives_total": len(representatives),
        "actionable_representatives_analyzed": len(selected_actionable),
        "exact_or_equivalent_urls_collapsed": len(actionable) - len(representatives),
        "primary_actionable_total": len(primary),
        "actionable_apexes_total": len(actionable_apexes),
        "actionable_apexes_analyzed": len(selected_apexes),
        "uninspected_representatives": max(
            0, len(representatives) - len(selected_actionable)
        ),
        "coverage_limited": len(selected_actionable) < len(representatives),
        "render_resources_total": len(resources),
        "render_resources_analyzed": sum(
            value.get("role") == "render_resource" for value in selected
        ),
    }
    return selected, coverage


def is_transient_url_error(data: object) -> bool:
    """Un délai réseau n'est pas un résultat d'inspection : il peut être rejoué."""
    if not isinstance(data, dict):
        return False
    error = str(data.get("error") or "")
    return error in TRANSIENT_URL_ERRORS or error.startswith("sandbox_request:")


async def _fetch_url_analysis(
    client: httpx.AsyncClient,
    settings: Settings,
    url: str,
    key: str,
    profile: str = "scanner",
) -> tuple[dict[str, object], str, Exception | None]:
    try:
        response = await client.post(
            f"{settings.url_sandbox_url}/fetch",
            json={"url": url, "decode_qr": True, "profile": profile},
            timeout=45,
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise TypeError("invalid URL sandbox response")
    except Exception as exc:  # noqa: BLE001 - preuve d'incomplétude
        parsed = urlsplit(url)
        return (
            {
                "initial_url": url,
                "initial_host": parsed.hostname or "",
                "initial_apex": _apex(parsed.hostname or ""),
                "url_hash": key,
                "analysis_incomplete": True,
                "error": f"sandbox_request:{type(exc).__name__}",
            },
            "error",
            exc,
        )
    data = _postgres_json_safe(value)
    if not isinstance(data, dict):
        raise TypeError("invalid sanitized URL sandbox response")
    return data, "ok", None


async def fetch_url_analysis_with_retry(
    client: httpx.AsyncClient,
    settings: Settings,
    url: str,
    key: str,
    apex_deja_muets: set[str] | None = None,
) -> tuple[dict[str, object], str, Exception | None]:
    """Rejoue une seule fois un délai réseau, sauf si l'apex s'est déjà tu.

    Le sandbox est un service distant : un délai isolé est souvent passager, et
    une seconde tentative évite qu'un aléa devienne une preuve manquante.

    Mais quand le même apex vient déjà de rendre un délai dans ce message, ce
    n'est plus un aléa - c'est un domaine durablement muet, et le rejeu double
    le coût précisément là où il ne rapportera rien. Le 18 août, seize URL d'un
    même apex ont été inspectées deux fois chacune sans jamais rien ramener.
    """
    data, status, exc = await _fetch_url_analysis(client, settings, url, key)
    if not is_transient_url_error(data):
        return data, status, exc
    apex = str(data.get("initial_apex") or "")
    if apex_deja_muets is not None and apex:
        if apex in apex_deja_muets:
            renonce = dict(data)
            renonce["retry_skipped"] = True
            renonce["retry_skip_reason"] = "apex_deja_muet"
            return renonce, status, exc
        apex_deja_muets.add(apex)
    retried, retried_status, retried_exc = await _fetch_url_analysis(
        client, settings, url, key
    )
    if not is_transient_url_error(retried):
        return retried, retried_status, retried_exc
    persistent = dict(retried)
    persistent["retry_attempted"] = True
    return persistent, retried_status, retried_exc


def _is_definitive_target_failure(error: object) -> bool:
    """Le lien est défaillant, pas notre analyse.

    Un domaine qui ne résout pas en DNS est une réponse, pas une panne : le
    bac à sable a fait son travail et constaté que la destination n'existe
    pas. Chez un spammeur, le lien mort est même un classique - domaine déjà
    désactivé, ou pas encore publié. Compter ce constat comme une analyse
    incomplète interdisait de classer le message et forçait une demande
    d'avis pour un fait qui, en réalité, accable l'expéditeur.
    """
    return str(error or "").startswith("blocked_url:dns_resolution_failed")


async def _analyze_urls(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    message_id: str,
    raw: bytes,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    candidates, resource_total = _message_url_candidates(raw)
    selected, coverage = _select_url_candidates(candidates)
    coverage["render_resources_total"] = resource_total
    results: list[dict[str, object]] = []
    # Les apex qui se sont déjà tus dans ce message : le rejeu ne s'obstine pas
    # sur eux. La mémoire vit le temps d'un message, jamais au-delà - un domaine
    # muet ce matin peut répondre cet après-midi.
    apex_deja_muets: set[str] = set()
    # Combien de liens ont déjà été redemandés sous une seconde identité.
    comparaisons = 0
    authenticated = await _message_is_dmarc_aligned(pool, message_id)
    for candidate in selected:
        url = candidate["url"]
        key = hashlib.sha256(url.encode()).hexdigest()
        if is_single_use_or_side_effect_url(url) or _SIDE_EFFECT_LINK_TEXT.search(
            candidate.get("visible_text", "")
        ):
            data = {
                "initial_url": url,
                "analysis_skipped": True,
                "skip_reason": "protected_single_use_or_side_effect_url",
                "sender_dmarc_aligned": authenticated,
            }
            await _save_analysis(
                pool, message_id, "url", key, "url-sandbox", "skipped", data
            )
            results.append(_url_summary(data, key, candidate))
            continue
        if candidate.get("link_context") in {"footer", "secondary_navigation"}:
            data = {
                "initial_url": url,
                "analysis_skipped": True,
                "skip_reason": "non_primary_navigation",
                "sender_dmarc_aligned": authenticated,
            }
            await _save_analysis(
                pool, message_id, "url", key, "url-sandbox", "skipped", data
            )
            results.append(_url_summary(data, key, candidate))
            continue
        cached = await pool.fetchrow(
            """
            SELECT status, result FROM external_analyses
            WHERE message_id=$1::uuid AND subject_kind='url'
              AND subject_key=$2 AND source='url-sandbox'
            """,
            message_id,
            key,
        )
        cached_result = _json_object(cached["result"]) if cached is not None else {}
        if (
            cached is not None
            and cached["status"] == "ok"
            and not is_transient_url_error(cached_result)
        ):
            data = cached_result
        else:
            debut = datetime.now(timezone.utc)
            data, status, exc = await fetch_url_analysis_with_retry(
                client, settings, url, key, apex_deja_muets=apex_deja_muets
            )
            # Second regard sous une autre identité, quand il peut apprendre
            # quelque chose. Un site qui sert deux pages différentes selon qui
            # demande ne se voit pas autrement : un seul profil reçoit la page
            # que le site a choisi de lui montrer, et la croit unique.
            if should_compare_profiles(
                data, authenticated=authenticated, deja_compares=comparaisons
            ):
                comparaisons += 1
                autre, _, _ = await _fetch_url_analysis(
                    client, settings, url, key, profile="browser"
                )
                data = dict(data)
                data["profile_comparison"] = compare_profiles(data, autre)
            # Une panne de persistance est opérationnelle : elle doit faire
            # échouer/rejouer le run, jamais se déguiser en finding sandbox.
            await _save_analysis(
                pool, message_id, "url", key, "url-sandbox", status, data, exc,
                started_at=debut,
            )
        explained_limit = _explained_authenticated_redirect_limit(data, authenticated)
        explained_fetch_error = _explained_authenticated_same_apex_fetch_error(
            data, authenticated
        )
        explained_limit = explained_limit or explained_fetch_error
        if explained_limit:
            data = dict(data)
            data["navigation_limit_explained"] = True
            data["navigation_limit_reason"] = (
                "authenticated_same_apex_fetch_error"
                if explained_fetch_error
                else "authenticated_https_chain_stable_on_final_apex"
            )
        results.append(_url_summary(data, key, candidate))
    _contextualize_equivalent_url_limits(results, authenticated)
    complete = all(
        value.get("role") == "render_resource"
        or value.get("analysis_skipped")
        or value.get("navigation_limit_explained")
        or _is_definitive_target_failure(value.get("error"))
        or not (value.get("error") or value.get("analysis_incomplete"))
        for value in results
    )
    coverage["actionable_analyzed"] = sum(
        value.get("role") != "render_resource" for value in results
    )
    coverage["render_resources_analyzed"] = sum(
        value.get("role") == "render_resource" for value in results
    )
    return results, complete, coverage


async def _analyze_attachments(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    message_id: str,
    raw: bytes,
) -> tuple[list[dict[str, object]], bool]:
    parts = _part_payloads(raw)
    rows = await pool.fetch(
        """
        SELECT path, filename, content_type, decoded_size_bytes, decoded_sha256
        FROM mime_parts WHERE message_id=$1::uuid AND is_attachment=true
        ORDER BY ordinal
        """,
        message_id,
    )
    results: list[dict[str, object]] = []
    complete = len(rows) <= MAX_ATTACHMENTS
    for row in rows[:MAX_ATTACHMENTS]:
        path = str(row["path"])
        key = str(row["decoded_sha256"] or path)
        item = parts.get(path)
        if item is None or len(item[2]) > MAX_ATTACHMENT_BYTES:
            complete = False
            data = {
                "path": path,
                "filename": row["filename"],
                "content_type": row["content_type"],
                "sha256": key,
                "analysis_incomplete": True,
                "reason": "payload_unavailable_or_too_large",
            }
            await _save_analysis(
                pool, message_id, "attachment", key, "file-sandbox", "skipped", data
            )
            results.append(_attachment_summary(data))
            continue
        filename, content_type, payload = item
        cached = await pool.fetchrow(
            """
            SELECT status, result FROM external_analyses
            WHERE message_id=$1::uuid AND subject_kind='attachment'
              AND subject_key=$2 AND source='file-sandbox'
            """,
            message_id,
            key,
        )
        if cached is not None and cached["status"] == "ok":
            data = _json_object(cached["result"])
        else:
            try:
                response = await client.post(
                    f"{settings.file_sandbox_url}/analyze",
                    json={
                        "filename": filename,
                        "content_b64": base64.b64encode(payload).decode("ascii"),
                    },
                    timeout=35,
                )
                response.raise_for_status()
                value = response.json()
                if not isinstance(value, dict):
                    raise TypeError("invalid file sandbox response")
            except Exception as exc:  # noqa: BLE001 - preuve d'incomplétude
                complete = False
                data = {
                    "path": path,
                    "filename": filename,
                    "content_type": content_type,
                    "sha256": key,
                    "analysis_incomplete": True,
                    "reason": "file_sandbox_request_failed",
                    "error": type(exc).__name__,
                }
                await _save_analysis(
                    pool,
                    message_id,
                    "attachment",
                    key,
                    "file-sandbox",
                    "error",
                    data,
                    exc,
                )
            else:
                data = _postgres_json_safe(value)  # type: ignore[assignment]
                if not isinstance(data, dict):
                    raise TypeError("invalid sanitized file sandbox response")
                data.update(
                    {
                        "path": path,
                        "filename": filename,
                        "content_type": content_type,
                        "sha256": key,
                    }
                )
                # Comme pour les URL, une panne PostgreSQL doit déclencher le
                # retry du run au lieu de fabriquer une analyse incomplète.
                await _save_analysis(
                    pool,
                    message_id,
                    "attachment",
                    key,
                    "file-sandbox",
                    "ok",
                    data,
                )
        if data.get("analysis_incomplete"):
            complete = False
        data.update(
            {
                "path": path,
                "filename": filename,
                "content_type": content_type,
                "sha256": key,
            }
        )
        results.append(_attachment_summary(data))
    return results, complete


def _technical_limit_reason(error: object) -> str:
    value = str(error or "analysis_incomplete")
    labels = {
        "fetch_error:HttpProtocolError": (
            "réponse HTTP non prise en charge par le sandbox"
        ),
        "hop_timeout": "délai de réponse HTTP dépassé",
        "sandbox_total_timeout": "budget total de navigation dépassé",
        "too_many_redirects": "limite de redirections atteinte",
        "analysis_incomplete": "inspection non terminée",
    }
    if value in labels:
        return labels[value]
    if value.startswith("sandbox_request:"):
        return "service d’inspection URL indisponible"
    if value.startswith("blocked_url:"):
        return "navigation interdite par la politique anti-SSRF"
    return "limite technique du sandbox"


def _attachment_limit_reason(value: dict[str, object]) -> str:
    reason = str(value.get("reason") or "")
    labels = {
        "payload_unavailable_or_too_large": (
            "contenu indisponible ou supérieur au budget d’analyse"
        ),
        "file_sandbox_request_failed": "service d’inspection fichier indisponible",
    }
    if reason in labels:
        return labels[reason]
    findings = value.get("findings")
    if isinstance(findings, list):
        codes = [
            str(item.get("code"))
            for item in findings
            if isinstance(item, dict) and item.get("code")
        ]
        if codes:
            return "inspection partielle signalée par " + ", ".join(codes[:4])
    return "inspection du fichier non terminée"


async def _nature_facts(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit le cadre d'envoi observé par le hook, sans le recalculer."""
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='nature' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    # Un dossier analysé avant l'arrivée du hook n'a pas de cadre d'envoi : son
    # absence reste neutre, elle ne devient jamais une charge.
    return _json_object(facts) if facts is not None else {}


async def _content_context(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit ce que le hook content a constaté du message, sans le recalculer."""
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='content' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    context = _json_object(facts).get("content_context") if facts is not None else None
    return context if isinstance(context, dict) else {}


async def _headers_facts(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    """Relit ce que le hook headers a constaté, sans le recalculer.

    Le hook n'a pas accès à l'authentification : il ne peut consigner que le
    fait structurel (alignement syntaxique). C'est ici, où `authenticated`
    est connu, que ce fait peut devenir une corrélation favorable.
    """
    facts = await pool.fetchval(
        """
        SELECT hr.facts FROM hook_runs hr
        JOIN investigations i ON i.id=hr.investigation_id
        WHERE i.message_id=$1::uuid AND hr.hook_name='headers' AND hr.status='ok'
        ORDER BY hr.created_at DESC LIMIT 1
        """,
        message_id,
    )
    return _json_object(facts) if facts is not None else {}


async def _learned_signals(
    pool: asyncpg.Pool[Any], message_id: str, participant: str
) -> list[dict[str, object]]:
    """Ce que les qualifications passées disent des indices du message courant.

    L'utilisateur ne qualifie pas seulement un expéditeur : il qualifie un
    genre de message. Chaque feedback conserve les indices observés, ce qui
    permet de dire au juge combien de fois un même indice a accompagné une
    qualification humaine, pour d'autres expéditeurs. C'est un contexte
    probatoire de plus, jamais une décision : un indice fréquent dans les
    indésirables n'établit rien à lui seul.
    """
    rows = await pool.fetch(
        """
        WITH observed AS (
            SELECT DISTINCT c.clue_code
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            WHERE i.message_id=$1::uuid AND c.direction <> 'neutral'
        ), learned AS (
            SELECT code.value AS clue_code,
                   count(*) FILTER (WHERE l.label='legitimate') AS legitimate,
                   count(*) FILTER (
                       WHERE l.label IN ('spam','dangerous','suspect')
                   ) AS adverse,
                   count(DISTINCT l.sender_normalized) AS senders
            FROM labels l
            CROSS JOIN LATERAL jsonb_array_elements_text(
                coalesce(l.context->'signals','[]'::jsonb)
            ) AS code(value)
            WHERE l.is_ground_truth=true AND l.active=true
              AND lower(l.participant_email)=lower($2)
            GROUP BY code.value
        )
        SELECT learned.* FROM learned
        JOIN observed ON observed.clue_code=learned.clue_code
        WHERE learned.legitimate + learned.adverse >= 2
          -- Un indice présent dans tous les messages ne distingue rien : seule
          -- une orientation nette des qualifications passées est informative.
          AND greatest(learned.legitimate, learned.adverse)::numeric
              / (learned.legitimate + learned.adverse) >= 0.8
        ORDER BY learned.adverse DESC, learned.legitimate DESC
        LIMIT 12
        """,
        message_id,
        participant,
    )
    return [
        {
            "clue_code": str(row["clue_code"]),
            "confirmed_legitimate": int(row["legitimate"]),
            "confirmed_adverse": int(row["adverse"]),
            "distinct_senders": int(row["senders"]),
        }
        for row in rows
    ]


async def _history(pool: asyncpg.Pool[Any], message_id: str) -> dict[str, object]:
    current = await pool.fetchrow(
        """
        SELECT envelope_from, from_header, envelope_recipients,
               raw_size_bytes, captured_at,
               (facts->>'attachment_count')::int AS attachment_count
        FROM messages WHERE id=$1::uuid
        """,
        message_id,
    )
    if current is None:
        raise RuntimeError("message not found")
    address = parseaddr(str(current["from_header"] or ""))[1]
    address = (address or str(current["envelope_from"])).casefold()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    participant = str((current["envelope_recipients"] or [""])[0]).casefold()
    rows = await pool.fetch(
        """
        SELECT m.raw_size_bytes, m.captured_at,
               (m.facts->>'attachment_count')::int AS attachment_count
        FROM messages m
        WHERE m.id<>$1::uuid
          AND (lower(m.envelope_from)=$2 OR lower(m.from_header) LIKE $3)
          AND EXISTS (
              SELECT 1 FROM unnest(m.envelope_recipients) recipient
              WHERE lower(recipient)=$4
          )
        ORDER BY m.captured_at DESC LIMIT 200
        """,
        message_id,
        address,
        f"%<{address}>%",
        participant,
    )
    # Les labels sont lus par leurs colonnes propres : un apprentissage reste
    # opposable au prochain message même si le message d'origine a été purgé.
    labels = await pool.fetch(
        """
        SELECT l.label, count(*) AS count
        FROM labels l LEFT JOIN messages m ON m.id=l.message_id
        WHERE l.is_ground_truth=true AND l.active=true
          AND (
              (l.sender_normalized=$1 AND lower(l.participant_email)=$3)
              OR (
                  l.sender_normalized IS NULL
                  AND (lower(m.envelope_from)=$1 OR lower(m.from_header) LIKE $2)
                  AND EXISTS (
                      SELECT 1 FROM unnest(m.envelope_recipients) recipient
                      WHERE lower(recipient)=$3
                  )
              )
          )
        GROUP BY l.label
        """,
        address,
        f"%<{address}>%",
        participant,
    )
    feedback_rows = await pool.fetch(
        """
        SELECT l.label, l.created_at,
               left(coalesce(l.subject,m.subject,''),300) AS subject,
               left(coalesce(l.context->>'user_reason',''),1000) AS user_reason,
               left(coalesce(l.context->>'llm_explanation',''),1000) AS explanation,
               l.context->>'feedback_reason_code' AS feedback_reason_code
        FROM labels l LEFT JOIN messages m ON m.id=l.message_id
        WHERE l.is_ground_truth=true AND l.active=true
          AND (
              (l.sender_normalized=$1 AND lower(l.participant_email)=$3)
              OR (
                  l.sender_normalized IS NULL
                  AND (lower(m.envelope_from)=$1 OR lower(m.from_header) LIKE $2)
                  AND EXISTS (
                      SELECT 1 FROM unnest(m.envelope_recipients) recipient
                      WHERE lower(recipient)=$3
                  )
              )
          )
        ORDER BY l.created_at DESC LIMIT 20
        """,
        address,
        f"%<{address}>%",
        participant,
    )
    sizes = [int(row["raw_size_bytes"]) for row in rows]
    hours = [row["captured_at"].hour for row in rows]
    current_size = int(current["raw_size_bytes"])
    size_zscore: float | None = None
    if len(sizes) >= 5 and statistics.pstdev(sizes) > 0:
        size_zscore = (current_size - statistics.mean(sizes)) / statistics.pstdev(sizes)
    usual_hours = sorted(set(hours))
    label_counts = {str(row["label"]): int(row["count"]) for row in labels}
    persistent_hold = await pool.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM sender_policies sp
            WHERE EXISTS (
                SELECT 1 FROM messages m, unnest(m.envelope_recipients) recipient
                WHERE m.id=$1::uuid
                  AND lower(recipient)=lower(sp.participant_email)
            )
              AND sp.active=true AND sp.action='hold'
              AND ((sp.scope='sender' AND sp.value_normalized=$2)
                OR (sp.scope='domain' AND sp.value_normalized=$3))
        )
        """,
        message_id,
        address,
        domain,
    )
    persistent_allow = await pool.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM sender_policies sp
            WHERE EXISTS (
                SELECT 1 FROM messages m, unnest(m.envelope_recipients) recipient
                WHERE m.id=$1::uuid
                  AND lower(recipient)=lower(sp.participant_email)
            )
              AND sp.active=true AND sp.action='allow'
              AND ((sp.scope='sender' AND sp.value_normalized=$2)
                OR (sp.scope='domain' AND sp.value_normalized=$3))
        )
        """,
        message_id,
        address,
        domain,
    )
    domain_profile = await pool.fetchrow(
        """
        SELECT en.status,
               en.data->>'creation_date' AS creation_date,
               (en.data->>'age_days')::int AS age_days,
               ARRAY(
                   SELECT jsonb_array_elements_text(
                       coalesce(en.data->'countries','[]'::jsonb)
                   )
               ) AS countries
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND e.value_normalized=$2
        ORDER BY e.id LIMIT 1
        """,
        message_id,
        domain,
    )
    current_countries = await pool.fetch(
        """
        SELECT DISTINCT country
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        CROSS JOIN LATERAL jsonb_array_elements_text(
            coalesce(en.data->'countries','[]'::jsonb)
        ) country
        WHERE e.message_id=$1::uuid AND e.entity_type='ip'
          AND e.role LIKE 'header:received%'
        """,
        message_id,
    )
    historical_countries = await pool.fetch(
        """
        SELECT country, count(DISTINCT m.id) AS messages
        FROM messages m
        JOIN entities e ON e.message_id=m.id
        JOIN enrichments en ON en.id=e.enrichment_id
        CROSS JOIN LATERAL jsonb_array_elements_text(
            coalesce(en.data->'countries','[]'::jsonb)
        ) country
        WHERE m.id<>$1::uuid AND e.entity_type='ip'
          AND e.role LIKE 'header:received%'
          AND (lower(m.envelope_from)=$2 OR lower(m.from_header) LIKE $3)
          AND EXISTS (
              SELECT 1 FROM unnest(m.envelope_recipients) recipient
              WHERE lower(recipient)=$4
          )
        GROUP BY country ORDER BY messages DESC
        """,
        message_id,
        address,
        f"%<{address}>%",
        participant,
    )
    current_country_values = sorted(str(row["country"]) for row in current_countries)
    known_country_values = {
        str(row["country"]): int(row["messages"]) for row in historical_countries
    }
    learned_signals = await _learned_signals(pool, message_id, participant)
    apex = _apex(domain)
    # Apex éprouvé localement : une adresse jamais vue peut appartenir à un
    # domaine dont d'autres adresses ont déjà livré, toutes boîtes confondues.
    # Le label reste self-portant (voir _learned_signals) : la table `labels`
    # est interrogée directement, jamais via le message d'origine qui a pu
    # être purgé par la rétention.
    #
    # HIST-004 ne s'applique jamais quand l'adresse exacte a déjà un
    # historique (`rows` non vide) : les deux requêtes ci-dessous ne
    # payent donc leur coût que pour une adresse réellement nouvelle, au lieu
    # de tourner sur chaque message.
    if rows:
        apex_delivered_count = 0
        apex_track_record_age_days: int | None = None
        apex_adverse_labels = 0
    else:
        apex_track_record = await pool.fetchrow(
            """
            SELECT count(*) AS delivered_count, min(m.captured_at) AS first_seen
            FROM messages m
            WHERE m.id<>$1::uuid
              AND m.delivery_status='delivered'
              AND (
                  lower(split_part(m.envelope_from,'@',2))=$2
                  OR lower(split_part(m.envelope_from,'@',2)) LIKE $3
              )
            """,
            message_id,
            apex,
            f"%.{apex}",
        )
        apex_adverse_labels = await pool.fetchval(
            """
            SELECT count(*) FROM labels l
            WHERE l.is_ground_truth=true AND l.active=true
              AND l.label IN ('spam','dangerous')
              AND (
                  lower(split_part(coalesce(l.sender_normalized,''),'@',2))=$1
                  OR lower(split_part(coalesce(l.sender_normalized,''),'@',2)) LIKE $2
              )
            """,
            apex,
            f"%.{apex}",
        )
        apex_delivered_count = int((apex_track_record or {}).get("delivered_count") or 0)
        apex_first_seen = (apex_track_record or {}).get("first_seen")
        apex_track_record_age_days = (
            (current["captured_at"] - apex_first_seen).days
            if apex_first_seen is not None
            else None
        )
    # Ancienneté de sept jours minimum : sans elle, un envoi massif d'adresses
    # fraîches sous un même apex s'auto-blanchirait en quelques minutes.
    apex_established_locally = bool(
        apex_delivered_count >= 3
        and isinstance(apex_track_record_age_days, int)
        and apex_track_record_age_days >= 7
        and int(apex_adverse_labels or 0) == 0
    )
    # Langue habituelle du destinataire : la dominance se lit sur ce que ce
    # destinataire a effectivement reçu (delivered), toutes boîtes confondues
    # n'aurait aucun sens ici - c'est l'habitude du lecteur qui compte. Bornée
    # aux 200 messages délivrés les plus récents (sous-requête avec LIMIT,
    # triée sur l'index existant `ix_messages_captured_at`) : un destinataire
    # ancien ne doit pas faire agréger un historique sans plafond.
    recipient_language_rows = await pool.fetch(
        """
        SELECT language, count(*) AS occurrences
        FROM (
            SELECT c.facts->>'language' AS language
            FROM clues c
            JOIN investigations i ON i.id=c.investigation_id
            JOIN messages m ON m.id=i.message_id
            WHERE c.clue_code='NATURE_MESSAGE_LANGUAGE'
              AND m.id<>$1::uuid
              AND m.delivery_status='delivered'
              AND EXISTS (
                  SELECT 1 FROM unnest(m.envelope_recipients) recipient
                  WHERE lower(recipient)=$2
              )
            ORDER BY m.captured_at DESC
            LIMIT 200
        ) bounded
        GROUP BY language
        """,
        message_id,
        participant,
    )
    recipient_language_counts = {
        str(row["language"]): int(row["occurrences"])
        for row in recipient_language_rows
        if row["language"]
    }
    recipient_language_total = sum(recipient_language_counts.values())
    recipient_dominant_language = (
        max(recipient_language_counts, key=lambda lang: recipient_language_counts[lang])
        if recipient_language_counts
        else None
    )
    recipient_language_dominance = (
        round(recipient_language_counts[recipient_dominant_language] / recipient_language_total, 3)
        if recipient_dominant_language and recipient_language_total
        else None
    )
    return {
        "sender_address": address,
        "participant_email": participant,
        "learned_signals": learned_signals,
        "sender_domain": domain,
        "sender_apex": apex,
        "previous_message_count": len(rows),
        "first_seen": rows[-1]["captured_at"] if rows else current["captured_at"],
        "ground_truth_labels": label_counts,
        "ground_truth_feedback": [
            {
                "label": str(row["label"]),
                "subject": str(row["subject"] or ""),
                "user_reason": str(row["user_reason"] or ""),
                "explanation": str(row["explanation"] or ""),
                "feedback_reason_code": row["feedback_reason_code"],
                "created_at": row["created_at"],
            }
            for row in feedback_rows
        ],
        "persistent_hold": bool(persistent_hold),
        "persistent_allow": bool(persistent_allow),
        "usual_hours_utc": usual_hours,
        "current_hour_utc": current["captured_at"].hour,
        "hour_previously_seen": current["captured_at"].hour in usual_hours,
        "mean_size_bytes": round(statistics.mean(sizes), 2) if sizes else None,
        "size_zscore": round(size_zscore, 3) if size_zscore is not None else None,
        "current_size_bytes": current_size,
        "previous_attachment_rate": (
            round(sum(int(row["attachment_count"] or 0) > 0 for row in rows) / len(rows), 3)
            if rows
            else None
        ),
        "current_attachment_count": int(current["attachment_count"] or 0),
        "sender_domain_enriched": bool(domain_profile and domain_profile["status"] == "ok"),
        "sender_domain_creation_date": (
            domain_profile["creation_date"] if domain_profile else None
        ),
        "sender_domain_age_days": domain_profile["age_days"] if domain_profile else None,
        "sender_domain_countries": list(domain_profile["countries"] or []) if domain_profile else [],
        "current_transport_countries": current_country_values,
        "historical_transport_countries": known_country_values,
        "unfamiliar_transport_countries": sorted(
            set(current_country_values) - set(known_country_values)
        ),
        "apex_delivered_count": apex_delivered_count,
        "apex_track_record_age_days": apex_track_record_age_days,
        "apex_adverse_label_count": int(apex_adverse_labels or 0),
        "apex_established_locally": apex_established_locally,
        "recipient_language_total": recipient_language_total,
        "recipient_dominant_language": recipient_dominant_language,
        "recipient_language_dominance": recipient_language_dominance,
    }


_SENSITIVE_FORM_INPUTS = {
    "password": re.compile(
        r"(?:^|[_-])(?:password|passwd|passcode|session_password)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "one_time_code": re.compile(
        r"(?:^|[_-])(?:otp|mfa|2fa|securitycode|verificationcode)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "payment_card": re.compile(
        r"(?:^|[_-])(?:cvv|cvc|card(?:number)?|creditcard)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "bank_account": re.compile(
        r"(?:^|[_-])(?:iban|bankaccount|accountnumber)(?:$|[_-])",
        re.IGNORECASE,
    ),
    "generic_secret": re.compile(
        r"(?:^|[_-])(?:secret|recoverykey|privatekey)(?:$|[_-])",
        re.IGNORECASE,
    ),
}


def _sensitive_form_categories(value: dict[str, object]) -> list[str]:
    forms = value.get("forms")
    if not isinstance(forms, list):
        return []
    categories: set[str] = set()
    for form in forms:
        if not isinstance(form, dict):
            continue
        inputs = form.get("inputs")
        names = inputs if isinstance(inputs, list) else []
        for category, pattern in _SENSITIVE_FORM_INPUTS.items():
            if any(pattern.search(str(name)) for name in names):
                categories.add(category)
    return sorted(categories)


def _signals(
    urls: list[dict[str, object]],
    attachments: list[dict[str, object]],
    history: dict[str, object],
    complete: bool,
    *,
    authenticated: bool = False,
    nature: dict[str, object] | None = None,
    sender_apex: str = "",
    domain_ages: dict[str, int] | None = None,
    organisations: dict[str, set[str]] | None = None,
    sender_site: dict[str, str] | None = None,
    message_registers: set[str] | None = None,
    content_context: dict[str, object] | None = None,
    headers_facts: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    domain_ages = domain_ages or {}
    # Un groupe fait transiter ses liens par ses propres domaines : vu du seul
    # apex, cela ne se distingue pas d'une redirection vers un tiers. Le
    # titulaire RDAP tranche, quand le registre accepte de le dire.
    intra_group = same_organisation_destinations(
        urls, sender_apex=sender_apex, organisations=organisations or {}
    )
    if intra_group:
        signals.append(
            {
                "article_code": "DEEP-015",
                "destination_apexes": intra_group,
                "sender_apex": sender_apex,
            }
        )
    # Ce que l'expéditeur publie de lui-même, comparé à ce qu'il prétend faire.
    # C'est le seul angle qui reste quand toute la technique est en règle :
    # un serveur compromis garde son authentification, jamais son métier.
    site_text = str((sender_site or {}).get("text") or "")
    site_apex = str((sender_site or {}).get("apex") or sender_apex)
    direct_apexes = {
        str(value.get("initial_apex") or "")
        for value in urls
        if value.get("initial_apex")
    }
    verified_display = [
        value
        for value in urls
        if value.get("displayed_apex")
        and value.get("final_apex")
        and value.get("displayed_apex") == value.get("final_apex")
    ]
    verified_deception = [
        value
        for value in urls
        if value.get("displayed_apex")
        and value.get("final_apex")
        and value.get("displayed_apex") != value.get("final_apex")
    ]
    if verified_display:
        signals.append(
            {
                "article_code": "DEEP-009",
                "kind": "displayed_domain_final_convergence",
                "occurrences": len(verified_display),
                "apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in verified_display
                    }
                ),
            }
        )
    if verified_deception:
        signals.append(
            {
                "article_code": "DEEP-011" if authenticated else "DEEP-010",
                "kind": (
                    "authenticated_displayed_domain_final_mismatch"
                    if authenticated
                    else "displayed_domain_final_mismatch"
                ),
                "occurrences": len(verified_deception),
                "pairs": sorted(
                    {
                        (
                            str(value.get("displayed_apex") or ""),
                            str(value.get("final_apex") or ""),
                        )
                        for value in verified_deception
                    }
                ),
            }
        )
    # Le service conditionnel se juge avant la redirection : il établit une
    # dissimulation, là où une redirection ne fait que la rendre possible.
    signals.extend(_cloaking_signals(urls))
    cross_apex = [value for value in urls if value.get("cross_apex_redirect")]
    if cross_apex:
        pairs = sorted(
            {
                (
                    str(value.get("initial_apex") or ""),
                    str(value.get("final_apex") or ""),
                )
                for value in cross_apex
            }
        )
        finals_are_directly_observed = all(
            str(value.get("final_apex") or "") in direct_apexes
            for value in cross_apex
        )
        if authenticated and finals_are_directly_observed:
            signals.append(
                {
                    "article_code": "DEEP-006",
                    "kind": "authenticated_tracking_convergence",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )
        elif not authenticated:
            signals.append(
                {
                    "article_code": "DEEP-008",
                    "kind": "unauthenticated_cross_apex_redirect",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )
        else:
            signals.append(
                {
                    "article_code": "DEEP-001",
                    "kind": "cross_apex_redirect",
                    "occurrences": len(cross_apex),
                    "pairs": pairs,
                }
            )

    # Une destination actionnable, hors de l'apex de l'expéditeur, vers un
    # domaine fraîchement enregistré : le motif du phishing par abus d'ESP, où
    # un domaine établi et aligné DMARC renvoie vers un site créé la veille.
    # On tranche MÊME sous authentification - l'auth couvre l'émetteur, pas la
    # destination. Le discriminant contre les faux positifs (newsletters
    # authentifiées à redirection) est l'âge : elles pointent vers l'établi.
    fresh_destinations = sorted(
        {
            apex
            for value in urls
            if value.get("role") != "render_resource"
            and (apex := str(value.get("final_apex") or ""))
            and sender_apex
            and apex != sender_apex
            and isinstance(domain_ages.get(apex), int)
            and domain_ages[apex] < FRESH_DESTINATION_DAYS
        }
    )
    if fresh_destinations:
        signals.append(
            {
                "article_code": "DOMAIN-004",
                "kind": "recent_cross_apex_destination",
                "apexes": fresh_destinations,
                "age_days": min(domain_ages[apex] for apex in fresh_destinations),
                "sender_apex": sender_apex,
                "authenticated": authenticated,
            }
        )

    forms = [value for value in urls if value.get("forms")]
    sensitive_forms = [
        (value, categories)
        for value in forms
        if (categories := _sensitive_form_categories(value))
    ]
    deceptive_sensitive_forms = [
        (value, categories)
        for value, categories in sensitive_forms
        if not authenticated
        and bool(
            value.get("cross_apex_redirect")
            or (
                value.get("displayed_apex")
                and value.get("final_apex")
                and value.get("displayed_apex") != value.get("final_apex")
            )
        )
    ]
    if deceptive_sensitive_forms:
        signals.append(
            {
                "article_code": "DEEP-002",
                "kind": "contextually_deceptive_sensitive_url_forms",
                "occurrences": len(deceptive_sensitive_forms),
                "sensitive_categories": sorted(
                    {
                        category
                        for _, categories in deceptive_sensitive_forms
                        for category in categories
                    }
                ),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value, _ in deceptive_sensitive_forms
                        if value.get("final_apex")
                    }
                ),
                "context": "unauthenticated_and_redirect_or_display_mismatch",
            }
        )
    elif sensitive_forms:
        signals.append(
            {
                "article_code": "DEEP-014",
                "kind": "ambient_sensitive_form_without_deceptive_context",
                "occurrences": len(sensitive_forms),
                "sensitive_categories": sorted(
                    {
                        category
                        for _, categories in sensitive_forms
                        for category in categories
                    }
                ),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value, _ in sensitive_forms
                        if value.get("final_apex")
                    }
                ),
                "context": (
                    "authenticated_sender"
                    if authenticated
                    else "no_deceptive_link_correlation"
                ),
            }
        )
    elif forms:
        signals.append(
            {
                "article_code": "DEEP-007",
                "kind": "generic_url_forms",
                "occurrences": len(forms),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in forms
                        if value.get("final_apex")
                    }
                ),
            }
        )

    protected_action_urls = [
        value
        for value in urls
        if value.get("analysis_skipped")
        and value.get("skip_reason") == "protected_single_use_or_side_effect_url"
    ]
    if protected_action_urls:
        signals.append(
            {
                "article_code": "DEEP-013",
                "kind": "single_use_or_side_effect_url_not_visited",
                "occurrences": len(protected_action_urls),
                "roles": sorted(
                    {
                        str(value.get("role") or "unknown")
                        for value in protected_action_urls
                    }
                ),
            }
        )

    incomplete_urls = [
        value
        for value in urls
        if value.get("role") != "render_resource"
        and not value.get("navigation_limit_explained")
        and (value.get("error") or value.get("analysis_incomplete"))
    ]
    if incomplete_urls:
        signals.append(
            {
                "article_code": "DEEP-003",
                "kind": "url_incomplete",
                "occurrences": len(incomplete_urls),
                "url_references": [
                    {
                        "url_ref": str(value.get("url_hash") or "")[:12],
                        "role": value.get("role"),
                        "initial_apex": value.get("initial_apex"),
                        "final_apex": value.get("final_apex"),
                        "visible_text": value.get("visible_text"),
                        "error": value.get("error") or "analysis_incomplete",
                        "technical_reason": _technical_limit_reason(
                            value.get("error") or "analysis_incomplete"
                        ),
                    }
                    for value in incomplete_urls[:10]
                ],
            }
        )

    explained_navigation_limits = [
        value for value in urls if value.get("navigation_limit_explained")
    ]
    if explained_navigation_limits:
        signals.append(
            {
                "article_code": "DEEP-012",
                "kind": "authenticated_stable_redirect_limit",
                "occurrences": len(explained_navigation_limits),
                "final_apexes": sorted(
                    {
                        str(value.get("final_apex") or "")
                        for value in explained_navigation_limits
                        if value.get("final_apex")
                    }
                ),
            }
        )

    material_attachments: list[dict[str, object]] = []
    incomplete_attachments: list[dict[str, object]] = []
    for value in attachments:
        try:
            score = float(value.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        findings = value.get("findings")
        severe = any(
            isinstance(item, dict) and item.get("severity") in {"high", "critical"}
            for item in (findings if isinstance(findings, list) else [])
        )
        if score >= 0.7 or severe:
            material_attachments.append(value)
        if value.get("analysis_incomplete"):
            incomplete_attachments.append(value)
    # Ce que le bac à sable a réellement vu, constat par constat. L'ancien
    # signal unique disait « quelque chose de matériel » sans dire quoi : une
    # macro, une archive chiffrée et un PDF qui lance un programme y étaient
    # indiscernables, et tout ce qui passait sous le seuil disparaissait.
    signals.extend(attachment_clues(attachments))
    if incomplete_attachments:
        signals.append(
            {
                "article_code": "DEEP-005",
                "kind": "file_incomplete",
                "occurrences": len(incomplete_attachments),
                "attachment_references": [
                    {
                        "file_ref": str(value.get("sha256") or "")[:12],
                        "filename": value.get("filename"),
                        "content_type": value.get("content_type") or value.get("mime"),
                        "reason": value.get("reason"),
                        "error": value.get("error"),
                        "technical_reason": _attachment_limit_reason(value),
                    }
                    for value in incomplete_attachments[:10]
                ],
            }
        )
    labels = history.get("ground_truth_labels") or {}
    legitimate = int(labels.get("legitimate", 0)) if isinstance(labels, dict) else 0
    adverse = sum(
        int(labels.get(name, 0))
        for name in ("spam", "suspect", "dangerous")
        if isinstance(labels, dict)
    )
    if legitimate >= 3 and adverse == 0:
        signals.append(
            {"article_code": "HIST-001", "kind": "confirmed_sender", "count": legitimate}
        )
    # Un envoi de masse est légitime quand le destinataire l'a demandé. Sans
    # aucun échange antérieur ni confirmation humaine, ce lien d'abonnement
    # n'est établi par rien : le cadre reste à la charge de l'expéditeur.
    if (
        isinstance(nature, dict)
        and nature.get("sending_mode") == "bulk"
        and int(history.get("previous_message_count") or 0) == 0
        and legitimate == 0
    ):
        signals.append(
            {
                "article_code": "NATURE-002",
                "kind": "unsolicited_bulk",
                "unsubscribe_offered": bool(nature.get("unsubscribe_offered")),
                "claim_registers": list(nature.get("claim_registers") or []),
            }
        )
    if int(history.get("previous_message_count") or 0) == 0:
        signals.append({"article_code": "HIST-002", "kind": "first_seen"})
        # Apex éprouvé localement : cette adresse précise est nouvelle, mais
        # d'autres adresses du même domaine ont déjà livré sans étiquette
        # défavorable - l'ancienneté et l'absence d'étiquette humaine
        # protègent contre un domaine qui s'auto-blanchirait vite.
        if history.get("apex_established_locally"):
            signals.append(
                {
                    "article_code": "HIST-004",
                    "kind": "apex_established_locally",
                    "apex": history.get("sender_apex"),
                    "delivered_count": history.get("apex_delivered_count"),
                    "apex_track_record_age_days": history.get(
                        "apex_track_record_age_days"
                    ),
                }
            )
    # Langue habituelle du destinataire : ce que ce destinataire précis reçoit
    # déjà très majoritairement, jamais ce que d'autres destinataires lisent.
    current_language = (nature or {}).get("language")
    recipient_language_total = int(history.get("recipient_language_total") or 0)
    recipient_language_dominance = float(
        history.get("recipient_language_dominance") or 0
    )
    if (
        current_language
        and current_language == history.get("recipient_dominant_language")
        and recipient_language_total >= 10
        and recipient_language_dominance >= 0.7
    ):
        signals.append(
            {
                "article_code": "HIST-005",
                "kind": "recipient_usual_language",
                "language": current_language,
                "recipient_language_total": recipient_language_total,
                "recipient_language_dominance": recipient_language_dominance,
            }
        )
    if history.get("persistent_allow"):
        signals.append(
            {"article_code": "POLICY-002", "kind": "authenticated_sender_allow"}
        )
    domain_age = history.get("sender_domain_age_days")
    if isinstance(domain_age, int) and domain_age < 90:
        signals.append(
            {
                "article_code": "DOMAIN-001",
                "kind": "recent_sender_domain",
                "age_days": domain_age,
                "creation_date": history.get("sender_domain_creation_date"),
            }
        )
    elif isinstance(domain_age, int) and domain_age >= 730:
        signals.append(
            {
                "article_code": "DOMAIN-002",
                "kind": "established_sender_domain",
                "age_days": domain_age,
                "creation_date": history.get("sender_domain_creation_date"),
            }
        )
    elif not history.get("sender_domain_enriched"):
        signals.append(
            {
                "article_code": "DOMAIN-003",
                "kind": "sender_domain_age_unavailable",
                "sender_domain": history.get("sender_domain"),
            }
        )
    # Cohérence transactionnelle : une notification déclenchée par l'action du
    # destinataire (confirmation, reçu, code) ne prouve rien seule - un
    # attaquant écrit aussi « confirmez votre commande ». Les trois faits
    # ensemble sont plus durs à contrefaire qu'aucun pris seul : aligner son
    # authentification sur un domaine établi depuis deux ans qu'on ne
    # contrôle pas coûte cher.
    transactional_purpose = str((content_context or {}).get("purpose") or "") in {
        "one_time_authentication",
        "account_security",
        "parcel_delivery",
        "payment",
    }
    if (
        transactional_purpose
        and authenticated
        and isinstance(domain_age, int)
        and domain_age >= 730
    ):
        signals.append(
            {
                "article_code": "CORR-012",
                "kind": "transactional_coherence",
                "purpose": (content_context or {}).get("purpose"),
                "domain_age_days": domain_age,
            }
        )
    # Désinscription RFC 8058 authentifiée : le hook headers ne consigne que
    # l'alignement syntaxique (HEADERS-004, neutre) - un From usurpé aligne
    # aussi facilement ses deux en-têtes qu'un expéditeur réel. Ce n'est que
    # combiné à une authentification DMARC réellement vérifiée que la
    # structure devient une preuve, faible et corrélée.
    if bool((headers_facts or {}).get("rfc8058_structure_aligned")) and authenticated:
        signals.append(
            {
                "article_code": "CORR-013",
                "kind": "authenticated_rfc8058_unsubscribe",
                "unsubscribe_apex": (headers_facts or {}).get("unsubscribe_apex"),
            }
        )
    zscore = history.get("size_zscore")
    # L'heure ne parle que pour un expéditeur aux horaires réguliers : un
    # émetteur déclenché par l'utilisateur (confirmation de commande...)
    # écrit à toute heure, et une heure jamais vue ne dit rien de lui. On ne
    # retient donc l'écart d'heure que pour un expéditeur au planning
    # concentré (peu d'heures distinctes vues jusqu'ici).
    usual_hours_utc = history.get("usual_hours_utc") or []
    regular_schedule = len(usual_hours_utc) <= 8
    unusual_hour = (
        int(history.get("previous_message_count") or 0) >= 10
        and regular_schedule
        and not history.get("hour_previously_seen")
    )
    unusual_country = bool(
        int(history.get("previous_message_count") or 0) >= 10
        and history.get("unfamiliar_transport_countries")
    )
    if (
        (isinstance(zscore, (float, int)) and abs(zscore) >= 3)
        or unusual_hour
        or unusual_country
    ):
        signals.append({"article_code": "HIST-003", "kind": "behavior_deviation"})
    if not complete:
        signals.append({"article_code": "POLICY-001", "kind": "incomplete_evidence"})
    return signals


async def _domain_ages(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, int]:
    """Âge RDAP par apex des domaines du message, quand il a été établi.

    On replie chaque domaine sur son apex : l'âge d'enregistrement est celui de
    l'apex, un sous-domaine (em7751.exemple.org) ne le change pas. On garde le
    plus petit âge observé par apex, par prudence.
    """
    rows = await pool.fetch(
        """
        SELECT e.value_normalized AS domain, (en.data->>'age_days')::int AS age_days
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND en.status='ok' AND en.data ? 'age_days'
        """,
        message_id,
    )
    ages: dict[str, int] = {}
    for row in rows:
        apex = _apex(str(row["domain"] or ""))
        age = row["age_days"]
        if not apex or age is None:
            continue
        ages[apex] = min(age, ages.get(apex, age))
    return ages


async def _domain_organisations(
    pool: asyncpg.Pool[Any], message_id: str
) -> dict[str, set[str]]:
    """Titulaire RDAP par apex, tel que le registre a bien voulu le dire.

    La donnée est déjà collectée par l'enrichissement : on la relit, sans
    aucun appel réseau supplémentaire.
    """
    rows = await pool.fetch(
        """
        SELECT e.value_normalized AS domain,
               en.data->'rdap'->'raw' AS rdap,
               en.data->'dns'->'ns' AS ns
        FROM entities e JOIN enrichments en ON en.id=e.enrichment_id
        WHERE e.message_id=$1::uuid AND e.entity_type='domain'
          AND en.status='ok'
          AND (en.data->'rdap' ? 'raw' OR en.data->'dns' ? 'ns')
        """,
        message_id,
    )
    organisations: dict[str, set[str]] = {}
    for row in rows:
        apex = _apex(str(row["domain"] or ""))
        if not apex:
            continue
        signature = organisations.setdefault(apex, set())
        raw = row["rdap"]
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = None
        if raw is not None:
            signature.update(organisation_signature(raw))
        # La délégation DNS atteste ce que le RDAP masqué et les certificats
        # de validation de domaine ne disent plus : pour déléguer un domaine
        # à ses propres serveurs, il faut le contrôler.
        ns = row["ns"] if "ns" in row.keys() else None
        if isinstance(ns, str):
            try:
                ns = json.loads(ns)
            except ValueError:
                ns = None
        signature.update(nameserver_signature(ns))
    return organisations


async def _sender_site(
    client: httpx.AsyncClient,
    settings: Settings,
    sender_apex: str,
    registers: set[str],
) -> dict[str, str] | None:
    """Ce que l'expéditeur publie sur sa page d'accueil, quand la question se pose.

    La visite n'a lieu que si le message se réclame d'une activité précise :
    sans registre invoqué, il n'y a rien à comparer, et rien ne justifie
    d'aller chercher un site de plus. C'est ce qui garde le coût négligeable.
    """
    if not sender_apex or not registers:
        return None
    value, _, error = await _fetch_url_analysis(
        client, settings, f"https://{sender_apex}/", "sender-site"
    )
    if error is not None:
        return None
    texte = str(value.get("body_excerpt") or "")[:4000]
    # Un hébergeur qui refuse l'entrée répond à la place de l'expéditeur. Sa
    # page ne dit rien du métier de celui-ci : la retenir reviendrait à lui
    # reprocher un contenu qu'il n'a pas écrit - c'est ce qui a fait retenir
    # une alerte de connexion OpenAI le 21 août, comparée à « Enable
    # JavaScript and cookies to continue ». Aucun site lu vaut mieux qu'un
    # site qui n'est pas le sien.
    if is_interstitial(texte):
        return None
    return {
        "apex": str(value.get("final_apex") or sender_apex),
        "text": texte,
    }


async def _identity_relation(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    display_name: str,
    from_apex: str,
) -> tuple[dict[str, object] | None, dict[str, object]]:
    """Cherche qui est ce nom, qui est ce domaine, puis fait juger le rapport.

    Trois garde-fous tiennent l'ensemble. Le premier : quand la recherche
    attribue le domaine émetteur à l'organisation cherchée, la question est
    close sans appeler personne - filiale, domaine régional, prestataire.
    Le deuxième : une panne, un quota ou une réponse hors format ne produit
    aucun indice. Le troisième : le modèle ne voit que deux noms et ce qu'une
    recherche publique en dit ; rien du message ne sort d'ici.
    """
    from sentimail_v3.code.identity_relation import (
        RELATION_PROMPT,
        appended_to_official,
        relation_clue,
        relation_question,
    )
    from sentimail_v3.code.organisation_lookup import belongs
    from sentimail_v3.observation.organisation_search import about_domain, about_name

    sur_le_nom, apexes = await about_name(pool, client, settings, display_name)
    if apexes and belongs(from_apex, apexes):
        _log(
            "deep.identity_relation_cleared",
            display_name=display_name[:60],
            from_apex=from_apex,
        )
        return None, {
            "searched": True,
            "cleared": True,
            "official_apexes": apexes,
        }
    imite = appended_to_official(from_apex, apexes)
    if imite:
        # Le domaine porte le nom d'un domaine officiel avec un mot en plus.
        # Le constat se lit sans avis, et le soumettre au modèle risquait ce
        # qu'il a fait : y voir un domaine de service de l'enseigne.
        _log("deep.identity_relation_appended", from_apex=from_apex, officiel=imite)
        return (
            {
                "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
                "article_code": "DEEP-022",
                "direction": "adverse",
                "strength": 65,
                "confidence": 0.9,
                "statement": (
                    f"Le message se présente au nom de {display_name.strip()[:80]}, "
                    f"depuis un domaine qui reprend celui de {imite} en y ajoutant "
                    "un mot. Un domaine officiel ne s'écrit pas ainsi."
                ),
                "facts": {
                    "from_apex": from_apex,
                    "claimed_organisation": display_name.strip()[:80],
                    "explication": (
                        f"{from_apex} n'est pas {imite} : il en reprend le nom "
                        "avec un mot en plus."
                    ),
                    "official_apexes": apexes[:3],
                    "verified_by": "search",
                },
            },
            {"searched": True, "appended_to": imite, "official_apexes": apexes},
        )
    sur_le_domaine = await about_domain(pool, client, settings, from_apex)
    try:
        content, _ = await provider_chat_json(
            pool,
            client,
            settings,
            messages=[
                {"role": "system", "content": RELATION_PROMPT},
                {
                    "role": "user",
                    "content": relation_question(
                        display_name=display_name,
                        from_apex=from_apex,
                        sur_le_nom=sur_le_nom,
                        sur_le_domaine=sur_le_domaine,
                        official_apexes=apexes,
                    ),
                },
            ],
            max_tokens=300,
            role="identity_claim",
        )
    except Exception as exc:  # noqa: BLE001 - une question sans réponse n'accuse pas
        _log("deep.identity_relation_error", error=type(exc).__name__)
        return None, {"searched": bool(sur_le_nom or sur_le_domaine), "error": True}
    start, end = content.find("{"), content.rfind("}")
    try:
        parsed = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        return None, {"searched": True, "unparsed": True}
    clue = relation_clue(
        parsed,
        display_name=display_name,
        from_apex=from_apex,
        official_apexes=apexes,
        searched=bool(sur_le_nom and sur_le_domaine),
    )
    return clue, {
        "searched": True,
        "results_on_name": len(sur_le_nom),
        "results_on_domain": len(sur_le_domaine),
        "official_apexes": apexes,
    }


def _display_name(from_header: str) -> str:
    """La partie lisible d'un en-tête « De », sans son adresse."""
    nom, _ = parseaddr(from_header)
    return nom.strip()


def _display_name_of(parsed: Any) -> str:
    """Le nom que le destinataire lit, pris là où le parseur le range.

    L'analyse profonde le cherchait sous « from », clé que le parseur n'écrit
    pas : le nom était donc toujours vide, et les deux contrôles qui reposent
    sur lui - l'identité revendiquée, la cohérence d'activité - jugeaient l'un
    sans jamais poser sa question, l'autre sans le nom qu'il croyait voir.
    Le passage par cette fonction est ce qui rend l'accord testable.
    """
    return _display_name(str(parsed.message.get("from_header") or ""))


async def _activity_coherence(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    site: dict[str, str] | None,
    subject: str,
    body: str,
    clue_codes: set[str],
    display_name: str = "",
) -> dict[str, object] | None:
    """Demande à un modèle si ce message peut émaner de cet expéditeur.

    L'appel est isolé et court : une question, une réponse binaire motivée. Il
    est aussi fail-soft - une panne du modèle ne produit aucun indice, et
    surtout aucune accusation par défaut.
    """
    headline = str((site or {}).get("text") or "")[:600]
    if not should_ask(headline, clue_codes):
        return None
    try:
        content, _ = await provider_chat_json(
            pool,
            client,
            settings,
            messages=[
                {"role": "system", "content": COHERENCE_PROMPT},
                {
                    "role": "user",
                    "content": coherence_question(
                        site_headline=headline,
                        display_name=display_name,
                        subject=subject,
                        body=body,
                    ),
                },
            ],
            max_tokens=300,
            role="activity_coherence",
        )
    except Exception as exc:  # noqa: BLE001 - une question sans réponse n'accuse pas
        _log("deep.coherence_error", error=type(exc).__name__)
        return None
    start, end = content.find("{"), content.rfind("}")
    try:
        parsed = json.loads(content[start : end + 1])
    except (ValueError, TypeError):
        return None
    return coherence_clue(parsed, sender_apex=str((site or {}).get("apex") or ""))


async def analyze_message(
    pool: asyncpg.Pool[Any],
    client: httpx.AsyncClient,
    settings: Settings,
    message_id: str,
) -> dict[str, object]:
    stored = await pool.fetchval(
        "SELECT raw_eml FROM messages WHERE id=$1::uuid", message_id
    )
    raw = reveal(stored, load_key(settings.raw_eml_key_file))
    if not isinstance(raw, bytes):
        raise TypeError("raw message unavailable")
    urls, urls_complete, url_coverage = await _analyze_urls(
        pool, client, settings, message_id, raw
    )
    attachments, attachments_complete = await _analyze_attachments(
        pool, client, settings, message_id, raw
    )
    history = await _history(pool, message_id)
    # Une panne ou une absence RDAP/WHOIS retire une information de contexte,
    # mais ne rend pas l'inspection matérielle du message incomplète.
    complete = urls_complete and attachments_complete
    authenticated = await _message_is_dmarc_aligned(pool, message_id)
    nature = await _nature_facts(pool, message_id)
    content_context = await _content_context(pool, message_id)
    headers_facts = await _headers_facts(pool, message_id)
    sender_apex = _apex(str(history.get("sender_domain") or ""))
    domain_ages = await _domain_ages(pool, message_id)
    organisations = await _domain_organisations(pool, message_id)
    parsed = parse_message(raw)
    registers = activity_registers(
        str(parsed.message.get("subject") or ""),
        str(parsed.message.get("body_text") or "")[:8000],
    )
    sender_site = await _sender_site(client, settings, sender_apex, registers)
    # Deux enquêteurs ont besoin de cette même page. La lire une fois par
    # enquêteur payait deux fois le même aller-retour ; quand le message
    # n'invoque aucun registre, la lecture ci-dessus n'a pas eu lieu et il
    # faut la faire ici.
    site_partage = sender_site or await _sender_site(
        client, settings, sender_apex, {"coherence"}
    )
    # Les enquêteurs qui ont besoin du monde extérieur passent par leur
    # registre : chacun est exécuté, chacun rend compte, et le superviseur peut
    # constater qu'ils ont bien tourné. Enterré dans cette fonction, un tel
    # contrôle disparaissait en silence dès qu'un chemin le contournait.
    contexte = SimpleNamespace(
        pool=pool,
        client=client,
        settings=settings,
        message_id=message_id,
        clue_codes={
            str(row["clue_code"])
            for row in await pool.fetch(
                """
                SELECT DISTINCT c.clue_code FROM clues c
                JOIN investigations i ON i.id=c.investigation_id
                WHERE i.message_id=$1::uuid
                """,
                message_id,
            )
        },
        sender_apex=sender_apex,
        subject=str(parsed.message.get("subject") or ""),
        body=str(parsed.message.get("body_text") or ""),
        # Le nom que le destinataire lit. C'est lui qui porte l'identité
        # revendiquée, et le domaine qui dit qui a réellement envoyé : les
        # comparer est le seul moyen de voir un message se présenter sous une
        # identité qui n'est pas la sienne.
        display_name=_display_name_of(parsed),
        sender_site=site_partage,
    )
    deep_hook_results = await run_deep_hooks(list(DEEP_HOOKS), contexte)
    deep_hook_clues = [
        clue for result in deep_hook_results for clue in result.clues
    ]
    signals = _signals(
        urls,
        attachments,
        history,
        complete,
        authenticated=authenticated,
        nature=nature,
        sender_apex=sender_apex,
        domain_ages=domain_ages,
        organisations=organisations,
        sender_site=sender_site,
        message_registers=registers,
        content_context=content_context,
        headers_facts=headers_facts,
    )
    signals.extend(deep_hook_clues)
    # Récidive de campagne : le squelette du message reprend-il celui d'un
    # message déjà qualifié ? Le label de la campagne source informe le juge,
    # la ressemblance seule ne décide de rien.
    try:
        campaign = await match_campaign(pool, message_id)
    except Exception:  # noqa: BLE001 - mémoire consultative, fail-soft
        campaign = None
    if campaign is not None:
        adverse = str(campaign["label"]) in {"spam", "dangerous", "suspect"}
        signals.append(
            {
                "article_code": "CORR-011",
                "clue_code": "TPLT_KNOWN_CAMPAIGN",
                "direction": "adverse" if adverse else "favorable",
                "strength": 55 if adverse else 20,
                "confidence": float(campaign["jaccard"]),
                "statement": (
                    "Ce message reprend le gabarit d’une campagne déjà "
                    f"qualifiée « {campaign['label']} »"
                    + (" (même objet)" if campaign.get("same_subject") else "")
                    + f", ressemblance {campaign['jaccard']}."
                ),
            }
        )
    return {
        "complete": complete,
        "deep_hook_runs": [
            {
                "hook_name": r.hook_name,
                "hook_version": r.hook_version,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "facts": r.facts,
                "error_type": r.error_type,
                "error_detail": r.error_detail,
            }
            for r in deep_hook_results
        ],
        "budgets": {
            "urls_base": BASE_URLS,
            "urls_hard_max": MAX_URLS,
            "urls_applied": url_coverage.get("adaptive_budget"),
            "attachments": MAX_ATTACHMENTS,
            "attachment_bytes": MAX_ATTACHMENT_BYTES,
        },
        "url_coverage": url_coverage,
        "url_analyses": urls,
        "attachment_analyses": attachments,
        "history": history,
        "sender_dmarc_aligned": authenticated,
        "signals": signals,
    }


_SIGNAL_RULES: dict[str, tuple[str, str, int, float, str]] = {
    "DEEP-015": (
        "URL_SAME_ORGANISATION_DESTINATION",
        "favorable",
        25,
        0.85,
        "La destination du lien appartient au même titulaire que le domaine expéditeur.",
    ),
    "DEEP-001": (
        "URL_SANDBOX_CROSS_APEX",
        "neutral",
        0,
        0.9,
        "Le sandbox observe une redirection inter-apex qui doit être expliquée.",
    ),
    "DEEP-002": (
        "URL_SANDBOX_FORM",
        "adverse",
        65,
        0.85,
        "Le contenu distant expose un formulaire demandant une donnée sensible.",
    ),
    "DEEP-003": (
        "URL_SANDBOX_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "Limite technique : au moins une URL n’a pas pu être entièrement inspectée.",
    ),
    "DEEP-004": (
        "ATTACHMENT_SANDBOX_MATERIAL",
        "adverse",
        100,
        0.98,
        "Le sandbox fichier relève un contenu actif ou malveillant matériel.",
    ),
    "DEEP-005": (
        "ATTACHMENT_SANDBOX_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "Limite technique : au moins une pièce jointe n’a pas pu être entièrement inspectée.",
    ),
    "DEEP-006": (
        "URL_AUTHENTICATED_TRACKING_CONVERGENCE",
        "favorable",
        25,
        0.9,
        "Les redirections d’un expéditeur authentifié convergent vers un apex aussi lié directement.",
    ),
    "DEEP-007": (
        "URL_GENERIC_FORM",
        "neutral",
        0,
        0.95,
        "La page distante contient un formulaire générique sans champ sensible détecté.",
    ),
    "DEEP-008": (
        "URL_UNAUTHENTICATED_CROSS_APEX",
        "adverse",
        35,
        0.75,
        "Un expéditeur non authentifié redirige vers un autre apex sans corrélation établie.",
    ),
    "DEEP-009": (
        "URL_DISPLAY_FINAL_CONVERGENCE",
        "favorable",
        25,
        0.95,
        "Le domaine affiché converge vers la destination finale après le lien de suivi.",
    ),
    "DEEP-010": (
        "URL_DISPLAY_FINAL_MISMATCH",
        "adverse",
        65,
        0.9,
        "Un expéditeur non authentifié présente un domaine différent de la destination finale vérifiée.",
    ),
    "DEEP-011": (
        "URL_AUTHENTICATED_DISPLAY_FINAL_MISMATCH",
        "neutral",
        0,
        0.95,
        "Un expéditeur authentifié présente un domaine différent de la destination finale ; le contexte doit l’expliquer.",
    ),
    "DEEP-012": (
        "URL_AUTHENTICATED_STABLE_REDIRECT_LIMIT",
        "neutral",
        0,
        0.95,
        "La limite de navigation est atteinte dans une chaîne HTTPS authentifiée qui boucle sur l’apex final.",
    ),
    "DEEP-013": (
        "URL_PROTECTED_ACTION_NOT_VISITED",
        "neutral",
        0,
        1.0,
        "Une URL à usage unique ou à effet de bord a été reconnue avant toute navigation et n’a pas été visitée.",
    ),
    "DEEP-014": (
        "URL_AMBIENT_SENSITIVE_FORM",
        "neutral",
        0,
        0.95,
        "Une page distante contient un formulaire sensible, mais le message ne présente pas de contexte trompeur corrélé permettant de l’imputer à sa demande.",
    ),
    "HIST-001": (
        "HISTORY_CONFIRMED_LEGITIMATE_SENDER",
        "favorable",
        30,
        0.9,
        "L’utilisateur a déjà confirmé plusieurs messages de cet expéditeur.",
    ),
    "HIST-002": (
        "HISTORY_FIRST_OBSERVATION",
        "neutral",
        0,
        1.0,
        "L’expéditeur ne dispose pas encore d’un historique local.",
    ),
    "HIST-003": (
        "HISTORY_BEHAVIOR_DEVIATION",
        "adverse",
        35,
        0.75,
        "L’heure ou la taille s’écarte des habitudes observées pour l’expéditeur.",
    ),
    "HIST-004": (
        "HISTORY_APEX_ESTABLISHED_LOCALLY",
        "favorable",
        25,
        0.85,
        "Cette adresse est nouvelle, mais son domaine a déjà livré plusieurs "
        "messages sans aucune étiquette défavorable, toutes boîtes confondues.",
    ),
    "HIST-005": (
        "HISTORY_RECIPIENT_USUAL_LANGUAGE",
        "favorable",
        15,
        0.8,
        "Le message est rédigé dans la langue que ce destinataire reçoit déjà très majoritairement.",
    ),
    "DOMAIN-001": (
        "SENDER_DOMAIN_RECENT",
        "adverse",
        55,
        0.9,
        "Le domaine de l’expéditeur a été créé récemment.",
    ),
    "DOMAIN-002": (
        "SENDER_DOMAIN_ESTABLISHED",
        "favorable",
        15,
        0.85,
        "Le domaine de l’expéditeur est établi depuis plusieurs années.",
    ),
    "DOMAIN-003": (
        "SENDER_DOMAIN_AGE_UNAVAILABLE",
        "neutral",
        0,
        1.0,
        "La date de création du domaine expéditeur n’a pas pu être établie.",
    ),
    "DOMAIN-004": (
        "URL_CROSS_APEX_FRESH_DESTINATION",
        "adverse",
        60,
        0.9,
        "Un lien actionnable mène, hors de l’apex de l’expéditeur, vers un "
        "domaine enregistré depuis peu ; l’authentification de l’expéditeur ne "
        "couvre pas la destination.",
    ),
    "CORR-012": (
        "CORRELATION_TRANSACTIONAL_COHERENCE",
        "favorable",
        25,
        0.85,
        "Le message est une notification transactionnelle authentifiée, "
        "envoyée depuis un domaine établi : trois faits réunis, difficiles à "
        "contrefaire ensemble.",
    ),
    "CORR-013": (
        "CORRELATION_AUTHENTICATED_RFC8058_UNSUBSCRIBE",
        "favorable",
        20,
        0.9,
        "Le message propose une désinscription en un clic sur le domaine de "
        "l’expéditeur, et cet expéditeur est authentifié.",
    ),
    # Écrit en juin, jeté en silence jusqu'au 27 août : le signal était produit,
    # mais aucune règle ne savait le dire. Le fait a pourtant été constaté sur
    # le courrier réel.
    "DEEP-020": (
        "URL_CONDITIONAL_SERVING",
        "adverse",
        75,
        0.9,
        "Un lien du message répond différemment selon l’identité de qui le demande.",
    ),
    # Même sort : un envoi de masse d'un expéditeur jamais vu, sans lien
    # d'abonnement établi, ne produisait rien.
    "NATURE-002": (
        "NATURE_UNSOLICITED_BULK_FIRST_CONTACT",
        "adverse",
        20,
        0.8,
        "Le message est un envoi de masse d’un expéditeur inconnu, sans abonnement établi.",
    ),
    "POLICY-001": (
        "EVIDENCE_INCOMPLETE",
        "neutral",
        0,
        1.0,
        "La chaîne de preuve profonde est incomplète ; ce manque n’est pas une preuve à charge.",
    ),
    "POLICY-002": (
        "AUTHENTICATED_SENDER_ALLOW",
        "favorable",
        25,
        1.0,
        "L’utilisateur a explicitement autorisé cet expéditeur exact par SMTP authentifié.",
    ),
}


async def persist_deep_hook_runs(
    pool: asyncpg.Pool[Any], investigation_id: str, results: list[Any]
) -> None:
    """Inscrit le passage de chaque enquêteur profond, abouti ou non.

    C'est cette trace qui rend la garantie d'exécution vérifiable : sans elle,
    on ne peut pas distinguer un contrôle qui n'a rien trouvé d'un contrôle qui
    n'a jamais tourné.
    """
    for order, value in enumerate(results, start=200):
        result = (
            SimpleNamespace(**value) if isinstance(value, dict) else value
        )
        await pool.execute(
            """
            INSERT INTO hook_runs (
                investigation_id, hook_name, hook_version, run_order, status,
                duration_ms, facts, error_type, error_detail
            ) VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
            """,
            investigation_id,
            result.hook_name,
            result.hook_version,
            order,
            result.status,
            result.duration_ms,
            _json(result.facts),
            result.error_type,
            result.error_detail,
        )


async def persist_signals(
    pool: asyncpg.Pool[Any], investigation_id: str, analysis: dict[str, object]
) -> None:
    raw_signals = analysis.get("signals")
    signals = raw_signals if isinstance(raw_signals, list) else []
    async with pool.acquire() as connection, connection.transaction():
        exists = await connection.fetchval(
            """
            SELECT EXISTS (
                SELECT 1 FROM hook_runs
                WHERE investigation_id=$1::uuid AND hook_name='deep_evidence'
            )
            """,
            investigation_id,
        )
        if exists:
            return
        await persist_deep_hook_runs(
            connection, investigation_id, analysis.get("deep_hook_runs") or []
        )
        hook_run_id = await connection.fetchval(
            """
            INSERT INTO hook_runs (
                investigation_id, hook_name, hook_version, run_order, status,
                duration_ms, facts
            ) VALUES ($1::uuid,'deep_evidence','2.2.0',100,'ok',0,$2::jsonb)
            RETURNING id
            """,
            investigation_id,
            _json(analysis),
        )
        edition_id = await connection.fetchval(
            "SELECT edition_id FROM investigations WHERE id=$1::uuid",
            investigation_id,
        )
        articles = {
            row["article_code"]: row
            for row in await connection.fetch(
                """
                SELECT id, article_code, title, principle, default_direction,
                       default_strength, severity, limitations, parameters
                FROM code_articles WHERE edition_id=$1 AND enabled=true
                """,
                edition_id,
            )
        }
        favorable = 0
        adverse = 0
        neutral = 0
        for ordinal, signal in enumerate(signals):
            if not isinstance(signal, dict):
                continue
            article_code = str(signal.get("article_code") or "")
            rule = _SIGNAL_RULES.get(article_code)
            if rule is None:
                # Certains signaux arrivent déjà qualifiés : ceux qui viennent
                # d'un jugement de sens, où la direction et l'énoncé sont le
                # résultat de l'appréciation, pas d'une table de traduction.
                if not signal.get("clue_code"):
                    # Un fait constaté qui ne sait pas se dire disparaît. Deux
                    # articles y sont restés des mois sans que rien ne le
                    # signale : le journal le dit désormais.
                    _log(
                        "deep.signal_untranslated",
                        article_code=article_code or "(sans article)",
                        kind=str(signal.get("kind") or ""),
                    )
                    continue
                clue_code = str(signal["clue_code"])
                direction = str(signal.get("direction") or "neutral")
                strength = int(signal.get("strength") or 0)
                confidence = float(signal.get("confidence") or 0.75)
                statement = str(signal.get("statement") or "")
            else:
                clue_code, direction, strength, confidence, statement = rule
            if article_code in {"DEEP-002", "DEEP-014"}:
                categories = signal.get("sensitive_categories")
                if isinstance(categories, list) and categories:
                    statement += " Catégories observées : " + ", ".join(
                        str(value) for value in categories
                    ) + "."
            elif article_code == "DEEP-003":
                references = signal.get("url_references")
                if isinstance(references, list) and references:
                    labels = []
                    for value in references[:4]:
                        if not isinstance(value, dict):
                            continue
                        label = str(value.get("visible_text") or "").strip()
                        labels.append(
                            (f"« {label} » — " if label else "")
                            + f"{value.get('initial_apex') or 'apex inconnu'} "
                            f"[réf. {value.get('url_ref') or '?'}] : "
                            f"{value.get('technical_reason') or 'inspection non terminée'}"
                        )
                    if labels:
                        statement += " URL concernées : " + "; ".join(labels) + "."
            elif article_code == "DEEP-005":
                references = signal.get("attachment_references")
                if isinstance(references, list) and references:
                    labels = []
                    for value in references[:4]:
                        if not isinstance(value, dict):
                            continue
                        labels.append(
                            f"{value.get('filename') or 'fichier sans nom'} "
                            f"[réf. {value.get('file_ref') or '?'}] : "
                            f"{value.get('technical_reason') or 'inspection non terminée'}"
                        )
                    if labels:
                        statement += " Fichiers concernés : " + "; ".join(labels) + "."
            if article_code == "HIST-001":
                strength = min(50, 20 + int(signal.get("count") or 0) * 3)
            elif article_code == "DOMAIN-001":
                strength = 70 if int(signal.get("age_days") or 0) < 30 else 35
                statement += (
                    f" Âge observé : {int(signal.get('age_days') or 0)} jours"
                    + (
                        f", création : {signal.get('creation_date')}."
                        if signal.get("creation_date")
                        else "."
                    )
                )
            elif article_code == "DOMAIN-002":
                statement += (
                    f" Âge observé : {int(signal.get('age_days') or 0)} jours"
                    + (
                        f", création : {signal.get('creation_date')}."
                        if signal.get("creation_date")
                        else "."
                    )
                )
            elif article_code == "DOMAIN-004":
                apexes = signal.get("apexes")
                statement += (
                    f" Destination : {', '.join(str(a) for a in apexes)}"
                    if isinstance(apexes, list) and apexes
                    else ""
                ) + f" ; âge observé : {int(signal.get('age_days') or 0)} jours."
            article = articles.get(article_code)
            snapshot = dict(article) if article else {}
            if snapshot.get("id") is not None:
                snapshot["id"] = str(snapshot["id"])
            await connection.execute(
                """
                INSERT INTO clues (
                    investigation_id, hook_run_id, article_id, article_code,
                    clue_code, direction, strength, confidence, statement,
                    facts, provenance, article_snapshot, ordinal
                ) VALUES (
                    $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,
                    '{"source":"deep-analysis"}'::jsonb,$11::jsonb,$12
                )
                """,
                investigation_id,
                hook_run_id,
                article["id"] if article else None,
                article_code,
                clue_code,
                direction,
                strength,
                confidence,
                statement,
                _json(signal),
                _json(snapshot),
                ordinal,
            )
            favorable += strength if direction == "favorable" else 0
            adverse += strength if direction == "adverse" else 0
            neutral += direction == "neutral"
        # Les convergences se calculent ici, et nulle part ailleurs : c'est le
        # seul moment où les indices statiques et l'analyse profonde sont tous
        # écrits. Elles deviennent des indices comme les autres, pour entrer au
        # dossier, au jugement et à l'apprentissage par la même porte.
        observed = {
            str(row["clue_code"])
            for row in await connection.fetch(
                "SELECT DISTINCT clue_code FROM clues WHERE investigation_id=$1::uuid",
                investigation_id,
            )
        }
        for ordinal, convergence in enumerate(correlations(observed), start=900):
            await connection.execute(
                """
                INSERT INTO clues (
                    investigation_id, hook_run_id, article_code, clue_code,
                    direction, strength, confidence, statement, facts,
                    provenance, ordinal
                ) VALUES (
                    $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,
                    '{"source":"correlation"}'::jsonb,$10
                )
                """,
                investigation_id,
                hook_run_id,
                convergence["article_code"],
                convergence["clue_code"],
                convergence["direction"],
                convergence["strength"],
                convergence["confidence"],
                convergence["statement"],
                _json(convergence["facts"]),
                ordinal,
            )
            adverse += int(convergence["strength"])
        await connection.execute(
            """
            UPDATE investigations SET
                favorable_points=favorable_points+$2,
                adverse_points=adverse_points+$3,
                neutral_clues=neutral_clues+$4,
                summary=summary || $5::jsonb
            WHERE id=$1::uuid
            """,
            investigation_id,
            favorable,
            adverse,
            neutral,
            _json({"deep_analysis_complete": bool(analysis.get("complete"))}),
        )


# Ce qu'une page vivante ne fait pas varier d'elle-même. Un texte qui change
# entre deux appels est banal - une date, un jeton, une personnalisation. Une
# destination, un statut ou un formulaire qui changent selon l'identité du
# visiteur, non : c'est du service conditionnel, c'est-à-dire du cloaking.
_CLOAKING_FACTS = ("final_apex", "final_status", "form_count")


def _profile_facts(rendu: dict[str, object]) -> dict[str, object]:
    formulaires = rendu.get("forms")
    return {
        "final_apex": rendu.get("final_apex"),
        "final_status": rendu.get("final_status"),
        "form_count": len(formulaires) if isinstance(formulaires, list) else 0,
    }


def compare_profiles(
    scanner: dict[str, object] | None,
    browser: dict[str, object] | None,
) -> dict[str, object]:
    """Compare deux rendus du même lien, obtenus sous deux identités.

    Quarante pour cent des URL de phishing servent une page anodine au scanner
    et la vraie page au visiteur. Un seul profil ne peut pas le voir : il faut
    demander deux fois et comparer.

    La comparaison ne porte que sur des faits de structure. Comparer le texte
    ferait de tout site daté ou personnalisé un cloaker, et un faux « dangereux »
    coûte plus cher ici qu'un signal manquant : l'empreinte de contenu est donc
    rapportée comme contexte, jamais comme preuve.

    Une comparaison impossible - un rendu absent ou en erreur - ne conclut pas
    au calme. Elle se déclare incomplète, et l'examen final en tient compte.
    """
    profils = [
        str((rendu or {}).get("profile") or defaut)
        for rendu, defaut in ((scanner, "scanner"), (browser, "browser"))
    ]
    exploitable = all(
        isinstance(rendu, dict) and not rendu.get("error")
        for rendu in (scanner, browser)
    )
    if not exploitable:
        return {
            "cloaking_detected": False,
            "comparison_incomplete": True,
            "divergences": [],
            "context": [],
            "evidence": {},
            "profiles": profils,
        }

    faits_scanner = _profile_facts(scanner or {})
    faits_browser = _profile_facts(browser or {})
    divergences = [
        nom for nom in _CLOAKING_FACTS if faits_scanner[nom] != faits_browser[nom]
    ]
    contexte = (
        ["content_digest"]
        if (scanner or {}).get("content_digest") != (browser or {}).get("content_digest")
        else []
    )
    return {
        "cloaking_detected": bool(divergences),
        "comparison_incomplete": False,
        "divergences": divergences,
        "context": contexte,
        "evidence": {
            nom: {profils[0]: faits_scanner[nom], profils[1]: faits_browser[nom]}
            for nom in divergences
        },
        "profiles": profils,
    }


# Une comparaison coûte une requête de plus. Trois par message suffisent à
# établir qu'un site sert deux pages différentes ; au-delà, on paie sans rien
# apprendre de neuf.
MAX_PROFILE_COMPARISONS = 3


def should_compare_profiles(
    rendu: dict[str, object],
    *,
    authenticated: bool,
    deja_compares: int,
) -> bool:
    """Faut-il redemander ce lien sous une seconde identité ?

    Pas partout : une seconde inspection de chaque lien doublerait le coût que
    l'on vient de réduire. Elle se réserve aux expéditeurs que rien n'authentifie,
    là où le cloaking se cache. Face à un expéditeur dont SPF, DKIM et DMARC
    s'alignent, se présenter en navigateur n'apprendrait rien et ferait sortir le
    bac à sable sous une fausse identité sans raison de le faire.

    Il faut aussi un premier rendu exploitable : sans lui, il n'y a rien à
    comparer.
    """
    if authenticated:
        return False
    if deja_compares >= MAX_PROFILE_COMPARISONS:
        return False
    if rendu.get("analysis_skipped") or rendu.get("error"):
        return False
    return True


def _cloaking_signals(urls: list[dict[str, object]]) -> list[dict[str, object]]:
    """Le service conditionnel établi, transformé en indice pesable.

    Ce n'est pas une redirection inter-apex, que tout prestataire de suivi
    pratique légitimement. C'est le même lien répondant différemment selon
    l'identité de qui demande : la page montrée au scanner n'est pas celle
    montrée au visiteur. Aucun service authentique n'a de raison de faire cela.

    N'avoir pas cherché n'accuse personne : seuls les liens réellement comparés
    et divergents produisent l'indice.
    """
    cloakes = [value for value in urls if value.get("cloaking_detected")]
    if not cloakes:
        return []
    divergences = sorted(
        {
            str(nom)
            for value in cloakes
            for nom in (value.get("cloaking_divergences") or [])
        }
    )
    return [
        {
            "article_code": "DEEP-020",
            "kind": "conditional_serving",
            "occurrences": len(cloakes),
            "divergences": divergences,
            "destinations": sorted(
                {
                    str(value.get("final_apex") or "")
                    for value in cloakes
                    if value.get("final_apex")
                }
            ),
        }
    ]
