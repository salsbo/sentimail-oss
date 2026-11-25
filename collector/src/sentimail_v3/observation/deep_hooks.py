"""Les enquêteurs qui ont besoin du monde extérieur, et leur garantie de passage.

Les dix hooks statiques n'ouvrent rien : ils lisent le message et concluent en
quelques millisecondes. Leur exécution est garantie par un pipeline unique, et
le superviseur alerte si l'un d'eux manque à l'appel.

D'autres questions ne se répondent pas sans sortir : visiter la page d'accueil
d'un expéditeur, demander à un modèle si le propos d'un message sied au métier
de qui l'écrit. Ces appels durent des secondes, échouent parfois, et n'ont donc
pas leur place parmi les hooks statiques - dont la pureté et la rapidité sont
justement ce qui les rend fiables.

Ils méritent pourtant la même garantie. Sans registre, un tel contrôle finit
enterré au milieu d'une fonction : rien ne dit s'il a tourné, rien n'alerte
quand il cesse de tourner, et il disparaît en silence le jour où un chemin
d'exécution le contourne. Ce module leur donne donc ce que les autres ont
déjà : une liste unique, une exécution tracée un par un, et un état - ok, skip
ou error - que le superviseur peut lire.

Règle commune à tous : un hook qui échoue ne produit aucun indice. Ne pas
savoir n'accuse personne.
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from sentimail_v3.observation.observation_cache import (
    fingerprint, load_observation, save_observation,
)


class DeepContext(Protocol):
    """Ce dont un enquêteur profond dispose pour travailler."""

    pool: Any
    client: Any
    settings: Any
    message_id: str
    clue_codes: set[str]
    sender_apex: str
    subject: str
    body: str
    display_name: str
    from_domain: str
    from_address: str
    sender_site: dict[str, str] | None
    organisations: dict[str, set[str]]
    url_analyses: list[dict[str, object]]


@dataclass(frozen=True)
class DeepHookResult:
    """Le compte rendu d'un passage, qu'il ait abouti ou non."""

    hook_name: str
    hook_version: str
    status: str
    duration_ms: float
    clues: list[dict[str, object]] = field(default_factory=list)
    facts: dict[str, object] = field(default_factory=dict)
    error_type: str | None = None
    error_detail: str | None = None
    cache_reused: bool = False


class DeepHook(ABC):
    """Contrat d'un enquêteur qui interroge le monde extérieur."""

    name: ClassVar[str]
    version: ClassVar[str]

    @abstractmethod
    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        """Retourne des indices déjà qualifiés et ses faits de travail."""


async def _cache_stage(hook: DeepHook, context: DeepContext) -> str | None:
    if not getattr(context, "observation_fingerprint", None):
        return None
    values = {name: getattr(context, name, None) for name in (
        "sender_apex", "subject", "body", "display_name", "from_domain",
        "from_address", "recipient", "sender_attested", "message_purpose",
        "sender_site", "url_analyses",
    )}
    values["clue_codes"] = sorted(getattr(context, "clue_codes", set()))
    values["organisations"] = {
        key: sorted(value) for key, value in (getattr(context, "organisations", None) or {}).items()
    }
    if hook.name == "cousin_domain":
        # Le hook précédent peut avoir enrichi cette mémoire. Son contenu,
        # relu ici, fait partie de l'entrée et non de la clé du début d'enquête.
        try:
            async with asyncio.timeout(2):
                values["official_memory"] = await context.pool.fetchval("""
                    SELECT md5(coalesce(jsonb_agg(jsonb_build_array(organisation,apexes)
                      ORDER BY organisation)::text,'[]')) FROM organisation_lookups
                """)
        except Exception:
            return None
    return f"hook:{hook.name}:" + fingerprint({"version": hook.version, "input": values})


def _remaining_hook_time(context: DeepContext) -> float:
    configured = getattr(getattr(context, "settings", None), "deep_hook_deadline_seconds", 45)
    try:
        seconds = float(configured)
    except (ValueError, TypeError):
        seconds = 45.0
    if not math.isfinite(seconds) or seconds <= 0:
        seconds = 45.0
    deadline = getattr(context, "analysis_deadline", None)
    return min(seconds, deadline-time.monotonic()) if deadline is not None else seconds


async def run_deep_hooks(
    hooks: list[DeepHook], context: DeepContext
) -> list[DeepHookResult]:
    """Fait passer chaque enquêteur, et rend compte de chacun.

    Aucun hook n'en empêche un autre : une panne se raconte, elle n'interrompt
    pas l'enquête. Un hook qui ne rend aucun indice sans échouer est « skip » -
    la question ne se posait pas ici, ce qui n'est pas la même chose qu'une
    question restée sans réponse.
    """
    results: list[DeepHookResult] = []
    for hook in hooks:
        started = time.perf_counter()
        try:
            seconds = _remaining_hook_time(context)
            if seconds <= 0:
                raise TimeoutError("budget total du dossier épuisé")
            async with asyncio.timeout(seconds):
                try:
                    stage = await _cache_stage(hook, context)
                except Exception:
                    stage = None
                key = getattr(context, "observation_fingerprint", None)
                cached = await load_observation(context.pool, context.message_id, stage, key) if stage else None
                if (cached and cached.get("status") in ("ok", "skip")
                    and isinstance(cached.get("clues"), list)
                    and all(isinstance(c, dict) for c in cached["clues"])
                    and isinstance(cached.get("facts"), dict)):
                    clues, facts = cached["clues"], cached["facts"]
                    reused = True
                else:
                    clues, facts = await hook.observe(context)
                    reused = False
        except Exception as exc:  # noqa: BLE001 - un enquêteur ne casse pas l'enquête
            results.append(
                DeepHookResult(
                    hook_name=hook.name,
                    hook_version=hook.version,
                    status="error",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    error_type=type(exc).__name__,
                    error_detail=(str(exc) or "délai de l'enquêteur dépassé")[:500],
                )
            )
            continue
        result = DeepHookResult(
                hook_name=hook.name,
                hook_version=hook.version,
                status="ok" if clues else "skip",
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                clues=[value for value in clues if isinstance(value, dict)],
                facts=facts if isinstance(facts, dict) else {},
                cache_reused=reused,
        )
        results.append(result)
        if stage and not reused:
            await save_observation(context.pool, context.message_id, stage, key, {
                "status": result.status, "clues": result.clues, "facts": result.facts,
            })
    return results


# « Fwd: », « Fw: », « TR: » : l'objet est celui du message transféré.
_FORWARD_SUBJECT = re.compile(r"^\s*(?:(?:fwd?|tr)\s*:\s*)+", re.IGNORECASE)


def _cited_only_on_crowd_mailbox(
    organisation: str, *, apex: str, display_name: str, subject: str, body: str
) -> bool:
    """Sur une messagerie publique, la marque n'est-elle écrite que dans le
    texte cité ou transféré ?

    Le compte gmail d'un proche n'est attesté que par son adresse : un proche
    qui écrit pour la première fois en transférant son avis de colis La Poste
    ou sa réservation Air France aurait été accusé d'usurper la marque qu'il
    cite (deux transferts de ce genre entre le 3 septembre et le 3 novembre
    2026). Hors messagerie publique, rien ne change : un fil cité peut être
    fabriqué, et un domaine propre répond de ce qu'il transfère.
    """
    from sentimail_v3.code.identity_relation import claimed_in_message
    from sentimail_v3.code.mail_profile import crowd_mailbox_domain
    from sentimail_v3.observation.message_parts import split_message_text

    if not apex or not crowd_mailbox_domain(apex):
        return False
    current, quoted = split_message_text(body)
    if not quoted.strip():
        return False
    own_subject = "" if _FORWARD_SUBJECT.match(subject or "") else subject
    return not claimed_in_message(
        organisation, display_name=display_name, subject=own_subject, text=current
    )


class SenderRelationHook(DeepHook):
    """Vérifie le rapport entre l'identité revendiquée et le domaine réel.

    Une identité concordante, réfutée, sans répondant ou non vérifiée reste
    tracée. Le métier et le contenu ont leur propre enquêteur : aucune de ces
    issues ne peut désormais interrompre leur confrontation.
    Le nom déguisé s'ajoute au constat quand le corps nomme l'organisation.
    """

    name: ClassVar[str] = "sender_relation"
    version: ClassVar[str] = "2.1.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.identity_relation import claimed_name
        from sentimail_v3.code.sender_relation import disguised_name_clue
        from sentimail_v3.code.sosies import nom_deguise

        clues, facts = await self._constat(context)
        organisation = str(facts.get("claimed_organisation") or "")
        if facts.get("claim_source") != "content" or not organisation:
            return clues, facts
        if any(clue.get("clue_code") == "SENDER_RELATION_CONSISTENT" for clue in clues):
            return clues, facts
        affiche = claimed_name(str(getattr(context, "display_name", "") or ""))
        imite = nom_deguise(affiche, organisation)
        if imite:
            from sentimail_v3.observation.deep_analysis import _sans_charge_si_atteste

            facts["disguised_as"] = imite
            clues.append(
                _sans_charge_si_atteste(
                    disguised_name_clue(
                        str(getattr(context, "sender_apex", "") or ""),
                        display_name=affiche,
                        organisation=organisation,
                        imite=imite,
                    ),
                    bool(getattr(context, "sender_attested", False)),
                )
            )
        return clues, facts

    async def _constat(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.identity_relation import (
            claimed_in_message,
            claimed_name,
            names_a_person,
            names_the_recipient,
            obvious_relation,
            relayed_organisation,
            worth_asking,
        )
        from sentimail_v3.code.sender_relation import (
            activity_readable,
            consistent_clue,
            footprint_clue,
            published_activity,
            unverified_clue,
        )
        from sentimail_v3.code.sosies import ecriture_du_message
        from sentimail_v3.observation.deep_analysis import (
            _claimed_organisation,
            _identity_relation,
            _sans_charge_si_cite,
        )
        from sentimail_v3.observation.organisation_search import (
            SearchUnavailable,
            about_domain,
        )

        apex = str(getattr(context, "sender_apex", "") or "")
        display_name = claimed_name(str(getattr(context, "display_name", "") or ""))
        subject = str(getattr(context, "subject", "") or "")
        body = str(getattr(context, "body", "") or "")
        site = getattr(context, "sender_site", None)
        facts: dict[str, object] = {
            "claimed_organisation": "",
            "claim_source": "",
            "activity_source": "",
            "outcome": "",
        }
        manques: list[str] = []

        # 1. Au nom de qui le message se présente. Le modèle propose, le
        # message confirme : une identité qu'il n'écrit pas ne compte pas.
        try:
            lu, claim_facts = await _claimed_organisation(
                context.pool,
                context.client,
                context.settings,
                display_name=display_name,
                subject=subject,
                body=body,
            )
        except Exception as exc:  # noqa: BLE001 - une lecture manquée se note, elle n'accuse pas
            lu, claim_facts = "", {"asked": True, "error": type(exc).__name__}
        if claim_facts.get("error"):
            manques.append("claim")
        facts["claim"] = claim_facts
        organisation, source = "", ""
        recipient = str(getattr(context, "recipient", "") or "")
        if lu and names_the_recipient(lu, recipient):
            # « Bonjour MARTIN ALICE » n'est pas une organisation : le nom du
            # destinataire ne part jamais vers la recherche.
            facts["claim_refused"] = "names_the_recipient"
            lu = ""
        # « X via Y », que le modèle le recopie ou que le nom affiché le porte :
        # c'est Y qui se confronte au domaine, jamais la personne X.
        lu = relayed_organisation(lu) if lu else ""
        affiche = relayed_organisation(display_name)
        if lu and claimed_in_message(lu, display_name=display_name, subject=subject, text=body):
            organisation, source = lu, "content"
        elif worth_asking(affiche, set()):
            # Le nom affiché, quand il désigne quelqu'un. L'ensemble vide
            # retire à cette fonction sa dispense d'expéditeur connu : ici on
            # regarde tout le monde. Une personne ne se cherche pas comme une
            # organisation, sauf quand le domaine porte déjà son nom : le
            # constat concordant reste alors écrit.
            if names_a_person(
                affiche, str(getattr(context, "from_address", "") or "")
            ) and not obvious_relation(affiche, apex):
                facts["claim_refused"] = "person_name"
            else:
                organisation, source = affiche, "display_name"
        # Le nom déguisé recopié tel quel (M-38cfc3, « AppIe ») : la recherche,
        # le démenti et DEEP-026 travaillaient sur le déguisement. Le message
        # écrit la marque ailleurs : c'est elle qu'il revendique.
        ecrite = ecriture_du_message(organisation, f"{subject} {body}") if organisation else ""
        if ecrite and ecrite != organisation and not names_the_recipient(ecrite, recipient):
            facts["claim_disguised"] = organisation
            organisation, source = ecrite, "content"
        facts["claimed_organisation"] = organisation
        facts["claim_source"] = source
        # Un particulier qui transfère son avis de colis depuis gmail ne parle
        # pas au nom de La Poste. Le constat reste écrit et lu par le juge, sans
        # charge : le texte « cité » est écrit par l'expéditeur lui-même, et un
        # faux transfert ne doit pas faire disparaître la marque du dossier.
        cited_only = source == "content" and _cited_only_on_crowd_mailbox(
            organisation, apex=apex, display_name=display_name, subject=subject, body=body
        )
        if cited_only:
            facts["claim_scope"] = "quoted_only_on_crowd_mailbox"

        # 2. Le rapport entre ce nom et le domaine réel.
        claim_found = False
        if organisation:
            if obvious_relation(organisation, apex):
                clue = consistent_clue(apex, organisation=organisation, how="domain_label")
                facts["outcome"] = clue["clue_code"]
                return [clue], facts
            clue, relation_facts = await _identity_relation(
                context.pool,
                context.client,
                context.settings,
                display_name=organisation,
                from_apex=apex,
                organisations=getattr(context, "organisations", None) or {},
                attested_locally=bool(getattr(context, "sender_attested", False)),
                from_domain=str(getattr(context, "from_domain", "") or ""),
            )
            facts["relation"] = relation_facts
            if clue is not None:
                if cited_only:
                    clue = _sans_charge_si_cite(clue)
                facts["outcome"] = str(clue.get("clue_code") or "")
                return [clue], facts
            if relation_facts.get("cleared"):
                clue = consistent_clue(apex, organisation=organisation, how="search")
                facts["outcome"] = clue["clue_code"]
                return [clue], facts
            if relation_facts.get("rapport") is True:
                # Le modèle a lu un rapport sur pièces : filiale, prestataire,
                # ancien nom. Concordant, et neutre comme les autres.
                clue = consistent_clue(apex, organisation=organisation, how="model")
                facts["outcome"] = clue["clue_code"]
                return [clue], facts
            if relation_facts.get("search_unavailable"):
                # Le moteur n'a pas répondu : c'est une panne, écrite comme
                # telle. Du 15 au 17 septembre 2026, une clé refusée a fait
                # passer « Amazon » pour un nom sans domaine et des newsletters
                # connues pour des expéditeurs sans répondant.
                facts["search_unavailable"] = str(relation_facts["search_unavailable"])
                manques.append("search_" + facts["search_unavailable"])
            elif relation_facts.get("error") or relation_facts.get("unparsed"):
                manques.append("relation")
            # L'organisation existe, la recherche a rendu ses domaines, et le
            # rapport n'est pas tranché : ce n'est pas un vide, et écrire
            # « ne désigne aucune organisation trouvable » serait faux.
            claim_found = bool(relation_facts.get("official_apexes"))

        # 3. Le propos contre le métier publié : la page d'accueil, sinon ce
        # que la recherche dit du domaine. Un moteur déjà constaté en panne
        # n'est pas rappelé : il tomberait pareil.
        domain_results: list[dict[str, Any]] = []
        if not facts.get("search_unavailable"):
            try:
                domain_results = await about_domain(
                    context.pool, context.client, context.settings, apex
                )
            except SearchUnavailable as exc:
                facts["search_unavailable"] = exc.kind
                manques.append("search_" + exc.kind)
            except Exception as exc:  # noqa: BLE001 - une recherche en panne n'est pas un vide
                manques.append("search:" + type(exc).__name__)
        activity, activity_source = published_activity(site, domain_results, from_apex=apex)
        facts["activity_source"] = activity_source
        if activity_readable(activity):
            # Un métier lisible ne prouve pas que l'identité revendiquée lui
            # appartient. Sa comparaison avec le contenu a son propre passage.
            clue = unverified_clue(apex, reason="identity_relation_undetermined")
            facts["outcome"] = clue["clue_code"]
            return [clue], facts

        # 4. Rien de lisible nulle part : le vide s'écrit, ou le manque.
        if manques or not getattr(context.settings, "search_api_key", ""):
            clue = unverified_clue(
                apex, reason=", ".join(manques) if manques else "search_unavailable"
            )
        elif claim_found:
            clue = unverified_clue(apex, reason="relation_undetermined")
        else:
            clue = footprint_clue(
                apex,
                claimed=organisation,
                results_on_domain=len(domain_results),
                site_read=bool(str((site or {}).get("text") or "").strip()),
            )
        facts["outcome"] = clue["clue_code"]
        return [clue], facts


class SenderActivityHook(DeepHook):
    """Confronte le contenu au métier, indépendamment du constat d'identité."""

    name: ClassVar[str] = "sender_activity"
    version: ClassVar[str] = "1.0.0"

    async def observe(self, context: DeepContext) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.sender_relation import activity_readable, published_activity
        from sentimail_v3.code.mail_profile import shared_sender_domain
        from sentimail_v3.observation.deep_analysis import _activity_coherence
        from sentimail_v3.observation.organisation_search import about_domain

        apex = str(getattr(context, "sender_apex", "") or "")
        if shared_sender_domain(apex):
            return [_activity_unverified(apex, "shared_infrastructure_not_sender_activity")], {
                "outcome": "unverified", "reason": "shared_infrastructure_not_sender_activity",
            }
        site = getattr(context, "sender_site", None)
        activity, source = published_activity(site, [])
        if not activity_readable(activity):
            try:
                results = await about_domain(context.pool, context.client, context.settings, apex)
            except Exception:  # noqa: BLE001 - une recherche manquée reste non concluante
                return [_activity_unverified(apex, "search_unavailable")], {"outcome": "unverified", "reason": "search_unavailable"}
            activity, source = published_activity(None, results, from_apex=apex)
        if not activity_readable(activity):
            return [_activity_unverified(apex, "no_readable_activity")], {"outcome": "unverified", "reason": "no_readable_activity"}
        clue = await _activity_coherence(
            context.pool, context.client, context.settings,
            {"apex": apex, "text": activity}, context.subject, context.body,
            set(context.clue_codes), str(getattr(context, "display_name", "") or ""),
            str(getattr(context, "message_purpose", "") or ""), always=True,
        )
        return [clue or _activity_unverified(apex, "model_silent")], {
            "activity_source": source, "outcome": (clue or {}).get("clue_code", "unverified"),
        }


def _activity_unverified(apex: str, reason: str) -> dict[str, object]:
    return {
        "clue_code": "SENDER_ACTIVITY_UNVERIFIED", "article_code": "DEEP-027",
        "direction": "neutral", "strength": 0, "confidence": 1.0,
        "statement": "Le rapport entre l'activité de l'expéditeur et le contenu n'a pas pu être établi.",
        "facts": {"from_apex": apex, "reason": reason},
    }


class ActionDestinationHook(DeepHook):
    """Compare la promesse du message aux destinations effectivement inspectées."""

    name: ClassVar[str] = "action_destination"
    version: ClassVar[str] = "1.0.0"

    async def observe(self, context: DeepContext) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.action_destination import observe_destinations
        return await observe_destinations(context)


class CousinDomainHook(DeepHook):
    """L'adresse d'envoi se lit-elle comme un domaine officiel sans l'écrire ?

    CORR-004 (domaine sosie, récent ou qui détourne les réponses) est resté
    actif du 27 août au 29 septembre 2026 sans que rien puisse produire son
    indice : la table de 108 marques écrite à la main qui le posait avait été
    retirée (0bbb14c). Il renaît sans liste.

    L'adresse d'envoi est comparée aux domaines que les recherches passées
    ont établis officiels (`organisation_lookups`, relue avec le filtre du
    nom) : même squelette de caractères sosies, écriture différente
    (`sosies.domaine_sosie`). La référence est ce que la recherche a rendu
    pour les organisations que le courrier réel a revendiquées ; rien ne sort
    d'ici. Il passe après `sender_relation`, qui vient d'écrire en mémoire les
    domaines de la revendication courante.

    Un apex que la recherche tient lui-même pour officiel n'imite personne ;
    un fait de propriété (délégation NS, signataire DKIM) l'écarte ; un
    domaine authentifié déjà livré le rend neutre.
    """

    name: ClassVar[str] = "cousin_domain"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.identity_relation import owned_by_official
        from sentimail_v3.code.organisation_lookup import belongs
        from sentimail_v3.code.sender_relation import cousin_domain_clue
        from sentimail_v3.code.sosies import domaine_sosie
        from sentimail_v3.observation.deep_analysis import _sans_charge_si_atteste
        from sentimail_v3.observation.organisation_search import official_memory

        apex = str(getattr(context, "sender_apex", "") or "")
        if not apex:
            return [], {"compared": 0}
        memoire = await official_memory(context.pool)
        facts: dict[str, object] = {"compared": len(memoire)}
        # Même règle que le premier garde-fou de la revendication : le domaine
        # que la recherche attribue à une organisation répond de lui-même.
        if belongs(apex, list(memoire)):
            facts["sender_official"] = True
            return [], facts
        from_domain = str(getattr(context, "from_domain", "") or "")
        imite = domaine_sosie(apex, sorted(memoire), from_domain=from_domain)
        if not imite:
            return [], facts
        facts["imite"] = imite
        proprietaire = owned_by_official(
            apex, [imite], getattr(context, "organisations", None) or {}
        )
        if proprietaire:
            facts["owned_via"] = proprietaire
            return [], facts
        clue = cousin_domain_clue(
            apex, from_domain=from_domain, imite=imite, organisation=memoire[imite]
        )
        return [
            _sans_charge_si_atteste(clue, bool(getattr(context, "sender_attested", False)))
        ], facts


class RequestedActionHook(DeepHook):
    """Que ce message demande-t-il concrètement de faire ?

    C'est ce qui sépare une gêne d'une perte : virer de l'argent, changer un
    RIB, livrer un code reçu. Le vocabulaire ne suffit pas à le dire - une
    mention n'est pas une demande - et le registre des actes est fermé, donc
    le modèle choisit dedans ou ne dit rien.
    """

    name: ClassVar[str] = "requested_action"
    version: ClassVar[str] = "1.3.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        import json

        from sentimail_v3.code.requested_action import (
            ACTION_PROMPT,
            action_clues,
            asks_to_disclose_code,
        )
        from sentimail_v3.llm import provider_chat_json
        from sentimail_v3.observation.message_parts import split_message_text

        texte = (context.body or "").strip()
        current, quoted = split_message_text(texte)
        if len(texte) < 20 and not (context.subject or "").strip():
            return [], {"asked": False, "reason": "message sans contenu lisible"}
        content, _ = await provider_chat_json(
            context.pool,
            context.client,
            context.settings,
            messages=[
                {"role": "system", "content": ACTION_PROMPT},
                {
                    "role": "user",
                    "content": f"Objet : {context.subject}\n\nTEXTE ACTUEL :\n{current[:2500]}"
                    + (f"\n\nFIL CITÉ (non authentifié) :\n{quoted[:1500]}" if quoted else ""),
                },
            ],
            max_tokens=300,
            role="requested_action",
        )
        start, end = content.find("{"), content.rfind("}")
        try:
            parsed = json.loads(content[start : end + 1])
        except (ValueError, TypeError):
            return [], {"asked": True, "parsed": False}
        lu = f"{context.subject}\n{texte}"
        clues = action_clues(parsed, lu)
        actions = [str(v) for v in (parsed.get("actions") or [])][:8]
        return clues, {
            "asked": True,
            "actions": actions,
            # Ce que le modèle a dit et que le texte n'a pas confirmé reste
            # tracé : l'écart se relit sans rejouer le modèle.
            "mfa_code_disclosure_unconfirmed": (
                "mfa_code_disclosure" in actions and not asks_to_disclose_code(lu)
            ),
        }


# Source unique : ajouter un enquêteur profond, c'est l'inscrire ici. L'ordre
# compte : les enquêteurs passent l'un après l'autre, et `cousin_domain` relit
# la mémoire que `sender_relation` vient de compléter.
DEEP_HOOKS: tuple[DeepHook, ...] = (
    SenderRelationHook(),
    CousinDomainHook(),
    SenderActivityHook(),
    RequestedActionHook(),
    ActionDestinationHook(),
)
