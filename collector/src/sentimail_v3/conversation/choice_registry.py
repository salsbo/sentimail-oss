"""Le registre unique des réponses A, B et C proposées par SentiMail.

Le sens d'une lettre, sa présentation et le texte prérempli vivent ensemble.
Les surfaces peuvent varier, mais A et B gardent une décision déterministe.
C reste une directive libre confiée au LLM, sans action implicite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, urlencode

from sentimail_v3.conversation.directive_policy import explicit_directive

VERT = "#15803d"
ROUGE = "#b91c1c"
GRIS = "#64748b"


@dataclass(frozen=True)
class ChoiceMeaning:
    """Le sens stable d'une lettre, indépendamment de sa présentation."""

    letter: str
    interpretation: str
    classification: str | None
    requested_action: str | None
    list_action: str | None


@dataclass(frozen=True)
class ChoicePresentation:
    """Les mots employés pour proposer une lettre sur une surface."""

    letter: str
    title: str
    subtitle: str
    phrase: str | None
    color: str

    def render_tuple(self) -> tuple[str, str, str, str]:
        return self.letter, self.title, self.subtitle, self.color


# C n'est pas une action. Il ouvre une directive libre que MAIA confie au LLM,
# puis aux mêmes garde-fous locaux que tout autre texte utilisateur.
CHOICE_MEANINGS = {
    "A": ChoiceMeaning("A", "deterministic", "legitimate", "release_original", "allow"),
    "B": ChoiceMeaning("B", "deterministic", "spam", "record_feedback", "hold"),
    "C": ChoiceMeaning("C", "llm", None, None, None),
}


# Les surfaces n'offrent pas toutes les mêmes gestes, mais leurs mots vivent
# ensemble. Changer un corps prérempli ici change donc aussi ce que le lecteur
# reconnaît comme un texte écrit par SentiMail.
CHOICE_PRESENTATIONS = {
    "review": (
        ChoicePresentation(
            "A",
            "Je le veux",
            "Cet expéditeur est fiable, livre-le-moi",
            "Merci pour ton avis. Je connais cet expéditeur et ce message est "
            "légitime : livre-le-moi.",
            VERT,
        ),
        ChoicePresentation(
            "B",
            "Non merci",
            "C’est indésirable, bloque cet expéditeur",
            "Merci pour ton avis. C'est du spam : ne le livre pas et bloque les "
            "prochains.",
            ROUGE,
        ),
        ChoicePresentation("C", "Autre chose", "J’explique à MAIA", None, GRIS),
    ),
    "junk": (
        ChoicePresentation(
            "A",
            "Livrer dans ma boîte",
            "Message légitime",
            "Merci pour ton avis, mais c'était une erreur : ce message est "
            "légitime, livre-le-moi.",
            VERT,
        ),
    ),
    "receipt": (
        ChoicePresentation(
            "A",
            "Livrer à nouveau",
            "Je me suis trompée : reçois-le",
            "Tu t'es trompée : c'est un message légitime, livre-le-moi à nouveau.",
            VERT,
        ),
        ChoicePresentation("C", "Autre commentaire", "J’explique à MAIA", None, GRIS),
    ),
    "digest": (
        ChoicePresentation(
            "A", "livrer", "livre-le, cet expéditeur est fiable", None, VERT
        ),
        ChoicePresentation(
            "B", "bloquer", "ne le livre pas, retiens les prochains", None, ROUGE
        ),
        ChoicePresentation(
            "C", "autre", "autre chose, explique après les deux-points", None, GRIS
        ),
    ),
}


FREEFORM_OPENING = "Voici ma demande à propos de ce message :"
FREEFORM_INVITE = "Tapez ici vos demandes ou remarques"


def choice_meaning(letter: str | None) -> ChoiceMeaning | None:
    return CHOICE_MEANINGS.get(str(letter or "").upper())


def choice_presentations(surface: str) -> tuple[ChoicePresentation, ...]:
    try:
        return CHOICE_PRESENTATIONS[surface]
    except KeyError as exc:
        raise ValueError(f"surface de choix inconnue : {surface}") from exc


def response_body(phrase: str | None) -> str:
    """Une réponse lisible, y compris l'amorce libre du choix C."""
    propos = phrase or f"{FREEFORM_OPENING}\n\n{FREEFORM_INVITE}"
    return f"Bonjour MAIA,\n\n{propos}\n\nMerci !\n"


def response_links(
    action_address: str,
    subject: str | dict[str, str],
    surface: str,
) -> dict[str, str]:
    """Les liens mailto d'une surface, construits depuis le registre."""
    if any(value in action_address for value in ("\r", "\n")):
        raise ValueError("invalid action address")
    links: dict[str, str] = {}
    for choice in choice_presentations(surface):
        choice_subject = (
            subject[choice.letter] if isinstance(subject, dict) else subject
        )
        links[choice.letter] = (
            "mailto:"
            + action_address
            + "?"
            + urlencode(
                {"subject": choice_subject, "body": response_body(choice.phrase)},
                quote_via=quote,
            )
        )
    return links


# Un « a » tapé seul sur un téléphone réglé en français devient « à », puis
# « À » en tête de message : le clavier corrige ce qu'il prend pour la
# préposition. Seule une ligne qui ne porte que cette lettre est pliée :
# « à demain » reste une phrase.
_A_ACCENTUE_SEUL = re.compile(r"^([ \t]*)[ÀÁÂàáâ]([.!]?[ \t]*)$", re.MULTILINE)


def fold_lone_accented_a(text: str) -> str:
    return _A_ACCENTUE_SEUL.sub(lambda m: m.group(1) + "A" + m.group(2), text or "")


# Un client mobile signe sous le bouton. Refuser le bouton à cause de la
# signature faisait d'un clic une phrase. La plus longue mesurée fait 34
# caractères ; au-delà de cette limite, ce n'est plus une signature.
SIGNATURE_LIMIT = 80


def prefilled_reply(user_text: str) -> tuple[str | None, str]:
    """Reconnaît un corps produit par le registre et isole le texte libre.

    Pour A et B, le second élément est ce qui suit le corps du bouton : vide
    quand le corps est intact, sinon une courte signature. Une queue qui porte
    une lettre ou une consigne n'est pas une signature : le texte n'est alors
    plus le bouton, et se lit comme une phrase.

    C reste une directive LLM : le retour ``C`` signifie seulement que le
    texte vient de l'amorce libre. Les lignes écrites par SentiMail sont
    retirées avant l'appel pour que le modèle ne les prenne pas pour les mots
    de l'utilisateur.
    """
    cleaned = user_text.strip()
    # Les blancs ne comptent pas : une réponse en HTML seul revient sans ses
    # lignes vides, et c'est pourtant le même bouton.
    flat = " ".join(cleaned.split())
    for presentations in CHOICE_PRESENTATIONS.values():
        for choice in presentations:
            if choice.phrase is None:
                continue
            body = " ".join(response_body(choice.phrase).split())
            if not flat.startswith(body):
                continue
            trailer = flat[len(body) :].strip()
            if not trailer:
                return choice.letter, ""
            if len(trailer) <= SIGNATURE_LIMIT and explicit_directive(trailer) == (
                None,
                None,
            ):
                return choice.letter, trailer
    if FREEFORM_OPENING not in cleaned and FREEFORM_INVITE not in cleaned:
        return None, cleaned
    ignored = {
        "Bonjour MAIA,",
        FREEFORM_OPENING,
        FREEFORM_INVITE,
        "Merci !",
    }
    detail = "\n".join(
        line.strip()
        for line in cleaned.splitlines()
        if line.strip() and line.strip() not in ignored
    ).strip()
    return "C", detail
