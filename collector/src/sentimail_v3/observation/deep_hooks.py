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

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol


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
    sender_site: dict[str, str] | None


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


class DeepHook(ABC):
    """Contrat d'un enquêteur qui interroge le monde extérieur."""

    name: ClassVar[str]
    version: ClassVar[str]

    @abstractmethod
    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        """Retourne des indices déjà qualifiés et ses faits de travail."""


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
            clues, facts = await hook.observe(context)
        except Exception as exc:  # noqa: BLE001 - un enquêteur ne casse pas l'enquête
            results.append(
                DeepHookResult(
                    hook_name=hook.name,
                    hook_version=hook.version,
                    status="error",
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    error_type=type(exc).__name__,
                    error_detail=str(exc)[:500],
                )
            )
            continue
        results.append(
            DeepHookResult(
                hook_name=hook.name,
                hook_version=hook.version,
                status="ok" if clues else "skip",
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                clues=[value for value in clues if isinstance(value, dict)],
                facts=facts if isinstance(facts, dict) else {},
            )
        )
    return results


class IdentityClaimHook(DeepHook):
    """Le nom affiché et le domaine qui écrit ont-ils un rapport ?

    Trois temps : le nom reprend-il déjà le domaine - alors il n'y a rien à
    chercher ; sinon on cherche dehors ce que chacun est ; puis le modèle lit
    les deux réponses et dit s'il y a un rapport.

    L'ordre est ce qui fait la différence. La question était posée au modèle
    seul, de mémoire, avec consigne de répondre « ça peut appartenir » dans le
    doute : un nom qu'il ignorait fermait donc la porte avant toute
    vérification. Il répond désormais sur pièces.

    L'indice est adverse ou absent, jamais favorable : un rapport plausible
    n'est pas une preuve d'authenticité, et rassurer sur cette base referait
    l'erreur que ce contrôle existe pour corriger.
    """

    name: ClassVar[str] = "identity_claim"
    version: ClassVar[str] = "2.0.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.identity_relation import obvious_relation, worth_asking
        from sentimail_v3.observation.deep_analysis import _identity_relation

        display_name = str(getattr(context, "display_name", "") or "")
        if not worth_asking(display_name, context.clue_codes):
            return [], {"asked": False, "reason": "nom affiché absent ou expéditeur connu"}
        if obvious_relation(display_name, context.sender_apex):
            # Le nom porte déjà le domaine : c'est le cas de presque tout le
            # courrier légitime, et rien ne part chercher.
            return [], {"asked": False, "reason": "le nom affiché reprend le domaine"}
        clue, facts = await _identity_relation(
            context.pool,
            context.client,
            context.settings,
            display_name=display_name,
            from_apex=context.sender_apex,
        )
        return ([clue] if clue else []), {"asked": True, **facts}


class ActivityCoherenceHook(DeepHook):
    """Le propos du message sied-il au métier de qui l'envoie ?

    La question ne se pose que pour un expéditeur dont on ne sait rien encore,
    et dont la page d'accueil dit quelque chose d'exploitable. Elle est confiée
    à un modèle : une liste de secteurs serait toujours incomplète, et chaque
    métier absent deviendrait soit une accusation injuste, soit une faille.
    """

    name: ClassVar[str] = "activity_coherence"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        from sentimail_v3.code.activity_coherence import should_ask
        from sentimail_v3.observation.deep_analysis import _activity_coherence

        site = getattr(context, "sender_site", None)
        headline = str((site or {}).get("text") or "")
        if not should_ask(headline, context.clue_codes):
            return [], {"asked": False, "reason": "site muet ou expéditeur connu"}
        clue = await _activity_coherence(
            context.pool,
            context.client,
            context.settings,
            site,
            context.subject,
            context.body,
            context.clue_codes,
            getattr(context, "display_name", ""),
        )
        facts: dict[str, object] = {
            "asked": True,
            "sender_apex": str((site or {}).get("apex") or context.sender_apex),
        }
        return ([clue] if clue else []), facts


class RequestedActionHook(DeepHook):
    """Que ce message demande-t-il concrètement de faire ?

    C'est ce qui sépare une gêne d'une perte : virer de l'argent, changer un
    RIB, livrer un code reçu. Le vocabulaire ne suffit pas à le dire - une
    mention n'est pas une demande - et le registre des actes est fermé, donc
    le modèle choisit dedans ou ne dit rien.
    """

    name: ClassVar[str] = "requested_action"
    version: ClassVar[str] = "1.0.0"

    async def observe(
        self, context: DeepContext
    ) -> tuple[list[dict[str, object]], dict[str, object]]:
        import json

        from sentimail_v3.code.requested_action import ACTION_PROMPT, action_clues
        from sentimail_v3.llm import provider_chat_json

        texte = (context.body or "").strip()
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
                    "content": f"Objet : {context.subject}\n\n{texte[:4000]}",
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
        clues = action_clues(parsed)
        return clues, {
            "asked": True,
            "actions": [str(v) for v in (parsed.get("actions") or [])][:8],
        }


# Source unique : ajouter un enquêteur profond, c'est l'inscrire ici.
DEEP_HOOKS: tuple[DeepHook, ...] = (
    ActivityCoherenceHook(),
    IdentityClaimHook(),
    RequestedActionHook(),
)
