"""Le contrôle de contenu, appliqué au texte lu dans les images et les fichiers.

Le hook ``content`` lit le corps visible du message, avant l'analyse profonde :
il n'a jamais vu ce que l'OCR tire d'une image ni ce qu'un PDF contient. Le
3 novembre 2026, un faux reçu Amazon de 400 $ tenait tout entier dans une image
(M-fc7f44) ; le corps visible faisait 12 caractères, la famille « contenu » est
restée muette et le message a été livré légitime à 0,95.

Ici, les mêmes motifs lisent le texte extrait des pièces jointes. Seuls les
constats qui chargent ou qui situent le message (urgence, demande sensible,
contexte financier...) en sortent : rien de ce qu'un attaquant écrit dans une
image ne peut créditer le message.
"""

from __future__ import annotations

from sentimail_v3.observation.dossier.hooks.content import ContentHook
from sentimail_v3.observation.dossier.models import Clue, InvestigationContext
from sentimail_v3.observation.parser import ParsedMessage

# Ce que le texte d'une image peut établir. Le reste du hook décrit la
# fabrication du message (HTML actif, texte masqué, objet en majuscules) ou
# des artefacts que l'OCR produit lui-même (mots coupés, alphabets mêlés), et
# ses constats favorables ou rassurants ne se lisent pas dans une image.
_FROM_IMAGES = frozenset(
    {
        "CONTENT_URGENCY",
        "CONTENT_SENSITIVE_REQUEST",
        "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
        "CONTENT_EXTORTION",
        "CONTENT_PROMPT_INJECTION_ATTEMPT",
        "CONTENT_FINANCIAL_CONTEXT",
    }
)
# Un document (conditions générales, contrat, avis d'échéance) parle
# légitimement de délais : sur le courrier du 3 septembre au 3 novembre 2026,
# l'urgence lue dans un PDF ne touchait que des envois légitimes (Revolut,
# une mutuelle). Une image qui tient lieu de corps n'a pas cette excuse.
_FROM_DOCUMENTS = _FROM_IMAGES - {
    "CONTENT_URGENCY",
    "CONTENT_SOCIAL_ENGINEERING_COMBINATION",
}
# Sous ce seuil, le corps visible ne dit rien : ce que lit le destinataire est
# l'image elle-même.
_IMAGE_BODY_MAX_VISIBLE_CHARS = 40
_MAX_TEXT_CHARS = 20_000


def _is_image(item: dict[str, object]) -> bool:
    return str(item.get("content_type") or item.get("mime") or "").startswith("image/")


def _extracted(attachments: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        item
        for item in attachments
        if isinstance(item.get("extracted_text"), str)
        and str(item["extracted_text"]).strip()
    ]


async def _content_clues(sources: list[dict[str, object]]) -> list[Clue]:
    text = "\n\n".join(str(item["extracted_text"]) for item in sources)[:_MAX_TEXT_CHARS]
    parsed = ParsedMessage(
        # L'objet et l'en-tête From sont déjà lus par le hook du corps : les
        # relire ici compterait deux fois la même urgence.
        message={"subject": "", "body_text": text, "body_html": "", "from_header": ""},
        headers=[],
        parts=[],
        facts={},
    )
    context = InvestigationContext(raw=b"", parsed=parsed, envelope_from="", recipients=[])
    clues, _ = await ContentHook().observe(context)
    return clues


def _signal(
    clue: Clue,
    sources: list[dict[str, object]],
    *,
    from_image: bool,
    visible_body_chars: int,
) -> dict[str, object]:
    body_is_image = from_image and visible_body_chars <= _IMAGE_BODY_MAX_VISIBLE_CHARS
    origin = "une image jointe" if from_image else "une pièce jointe"
    tail = (
        " Le corps du message ne contient presque aucun texte : ce que le "
        "destinataire lit est l’image."
        if body_is_image
        else ""
    )
    return {
        "article_code": clue.article_code,
        "clue_code": clue.clue_code,
        "direction": clue.direction,
        "strength": clue.strength,
        "confidence": clue.confidence,
        "statement": f"Dans le texte lu dans {origin} : " + clue.statement + tail,
        "facts": {
            **dict(clue.facts),
            "text_origin": "attachment",
            "text_sources": sorted(
                {str(item.get("extracted_text_source") or "extraction") for item in sources}
            ),
            "body_is_image": body_is_image,
            "visible_body_chars": visible_body_chars,
            "attachment_references": [
                {
                    "file_ref": str(item.get("sha256") or "")[:12],
                    "filename": item.get("filename"),
                    "content_type": item.get("content_type") or item.get("mime"),
                    "text_source": item.get("extracted_text_source"),
                }
                for item in sources[:5]
            ],
        },
    }


async def attachment_text_signals(
    attachments: list[dict[str, object]],
    *,
    visible_body_chars: int,
    already_observed: set[str] | frozenset[str] = frozenset(),
) -> list[dict[str, object]]:
    """Les indices de contenu que porte le texte extrait des pièces jointes."""
    sources = _extracted(attachments)
    images = [item for item in sources if _is_image(item)]
    documents = [item for item in sources if not _is_image(item)]
    signals: list[dict[str, object]] = []
    seen = set(already_observed)
    # Les images d'abord : si le même constat se lit des deux côtés, c'est
    # l'image, qui tient lieu de corps, qui le porte.
    for group, carried, from_image in (
        (images, _FROM_IMAGES, True),
        (documents, _FROM_DOCUMENTS, False),
    ):
        if not group:
            continue
        for clue in await _content_clues(group):
            if clue.clue_code not in carried or clue.clue_code in seen:
                continue
            if clue.direction == "favorable":
                continue
            seen.add(clue.clue_code)
            signals.append(
                _signal(
                    clue, group, from_image=from_image, visible_body_chars=visible_body_chars
                )
            )
    return signals
