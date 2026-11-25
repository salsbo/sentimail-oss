"""Extraction, sélection et résumé des destinations HTML et URL d'un message.

Regroupe les fonctions pures (sans base de données ni réseau) chargées de :
- séparer les liens activables des ressources de rendu dans le HTML ;
- prioriser et échantillonner les candidats URL selon le budget adaptatif ;
- résumer les constats du bac à sable URL et qualifier les limites techniques.
"""

from __future__ import annotations

import re
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

import tldextract

from sentimail_v3.observation.parser import parse_email

BASE_URLS = 20
MAX_URLS = 40
URLS_PER_APEX = 2
# Délais du sandbox : ils décrivent le réseau, pas la destination. Ils méritent
# une seconde tentative avant d'être retenus comme une inspection manquante.
TRANSIENT_URL_ERRORS = frozenset({"hop_timeout", "sandbox_total_timeout"})

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
        "qr_error": _bounded(data.get("qr_error")),
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
    root: EmailMessage = parse_email(raw)
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


def _is_definitive_target_failure(error: object) -> bool:
    """Le lien est défaillant, pas notre analyse.

    Un domaine qui ne résout pas en DNS est une réponse, pas une panne : le
    bac à sable a fait son travail et constaté que la destination n'existe
    pas. Chez un spammeur, le lien mort est même un classique - domaine déjà
    désactivé, ou pas encore publié. Compter ce constat comme une analyse
    incomplète interdisait de classer le message et forçait une demande
    d'avis pour un fait qui, en réalité, accable l'expéditeur.
    """
    value = str(error or "")
    return value in {
        "blocked_url:invalid_hostname",
        "blocked_url:invalid_port",
        "blocked_url:invalid_url",
        "blocked_url:missing_hostname",
        "redirect_without_location",
    } or value.startswith("blocked_url:dns_resolution_failed")
