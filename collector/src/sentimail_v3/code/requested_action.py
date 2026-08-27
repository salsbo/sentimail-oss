"""Ce que le message demande de faire - le critère qui sépare une gêne d'une perte.

Un indésirable veut qu'on lise. Une fraude veut qu'on vire de l'argent, qu'on
change des coordonnées bancaires, qu'on achète des cartes cadeaux ou qu'on
livre un code à usage unique. Les deux peuvent porter le même vocabulaire
d'urgence et la même authentification ; c'est l'acte réclamé qui les sépare, et
c'est lui qui dit ce qu'on risque.

L'acte réclamé ne se lit pas par mots-clés. « Peux-tu regarder si le RIB est à
jour » et « merci de mettre à jour nos coordonnées bancaires ci-jointes »
partagent leur vocabulaire et n'ont rien à voir. Une mention n'est pas une
demande, et un lien de désabonnement n'est pas un appel à cliquer. C'est donc
un jugement, confié à un modèle - comme la cohérence de métier, et pour la même
raison : la liste de motifs échouerait toujours.

Le registre des actions, lui, est fermé. Le modèle choisit dedans ou ne dit
rien : il ne peut pas inventer un critère, et chaque action nommée ici porte sa
gravité et son article, donc entre au jugement et à l'apprentissage comme les
autres.
"""

from __future__ import annotations

from typing import Any

# Registre fermé : code interne -> (article, force, énoncé lisible).
# La force dit ce que l'acte coûte s'il aboutit, pas la probabilité qu'il soit
# frauduleux : virer de l'argent est irréversible, cliquer ne l'est pas.
_ACTIONS: dict[str, tuple[str, int, str]] = {
    "payment_transfer": (
        "ACT-001", 80,
        "Le message demande d’effectuer un virement ou un paiement.",
    ),
    "bank_details_change": (
        "ACT-002", 80,
        "Le message demande de modifier des coordonnées bancaires.",
    ),
    "gift_card_purchase": (
        "ACT-003", 80,
        "Le message demande d’acheter des cartes cadeaux.",
    ),
    "credential_entry": (
        "ACT-004", 70,
        "Le message demande de saisir un identifiant ou un mot de passe.",
    ),
    "mfa_code_disclosure": (
        "ACT-005", 85,
        "Le message demande de communiquer un code de vérification reçu.",
    ),
    "identity_document": (
        "ACT-006", 70,
        "Le message demande d’envoyer une pièce d’identité ou un justificatif.",
    ),
    "file_execution": (
        "ACT-007", 75,
        "Le message demande d’ouvrir ou d’exécuter un fichier.",
    ),
    "software_install": (
        "ACT-008", 75,
        "Le message demande d’installer un logiciel ou un accès à distance.",
    ),
    "qr_code_scan": (
        "ACT-009", 55,
        "Le message demande de scanner un code QR.",
    ),
    "phone_callback": (
        "ACT-010", 55,
        "Le message demande d’appeler un numéro de téléphone.",
    ),
    "personal_data": (
        "ACT-011", 50,
        "Le message demande de communiquer des données personnelles.",
    ),
    "procedure_bypass": (
        "ACT-012", 75,
        "Le message demande de contourner une procédure habituelle.",
    ),
    "confidentiality": (
        "ACT-013", 60,
        "Le message demande de garder l’échange confidentiel.",
    ),
    "click_link": (
        "ACT-014", 25,
        "Le message invite à cliquer sur un lien.",
    ),
    "reply_message": (
        "ACT-015", 15,
        "Le message attend une réponse par courrier.",
    ),
    # Lire n'engage à rien : l'inscrire au dossier accuserait tout le courrier.
    # Le code existe pour que le modèle puisse répondre « rien de plus ».
    "read_only": ("", 0, ""),
}
KNOWN_ACTIONS = frozenset(_ACTIONS)

ACTION_PROMPT = """Tu identifies ce qu'un message demande concrètement à son
destinataire de faire. Rien d'autre : tu ne dis pas si le message est honnête,
tu ne le qualifies pas, tu ne le classes pas.

Une mention n'est pas une demande. Un message qui parle d'un virement passé ne
demande pas de virement ; un pied de page avec un lien de désabonnement ne
demande pas de cliquer. Ne retiens que ce qui est réellement attendu du
destinataire.

Fournir n'est pas réclamer, et c'est la distinction la plus importante ici.
« Votre code de vérification est 481920 » fournit un code : le message ne
demande rien, c'est mfa_code_disclosure=non. « Renvoyez-nous le code que vous
venez de recevoir » réclame de le communiquer : c'est mfa_code_disclosure=oui.
La même règle vaut partout : un message qui joint une facture ne demande pas
de facture, un message qui annonce un remboursement ne demande pas de
virement.

Réponds uniquement par cet objet JSON :
{"actions": ["..."], "explication": "une phrase courte"}

Choisis exclusivement parmi ces valeurs :
payment_transfer, bank_details_change, gift_card_purchase, credential_entry,
mfa_code_disclosure, identity_document, file_execution, software_install,
qr_code_scan, phone_callback, personal_data, procedure_bypass,
confidentiality, click_link, reply_message, read_only

read_only signifie que le message n'attend aucun acte : information, accusé de
réception, lettre d'information. Toute valeur hors de cette liste est ignorée."""


def action_clues(response: dict[str, Any] | None) -> list[dict[str, object]]:
    """Les indices tirés des actes réclamés, dans l'ordre du registre."""
    if not isinstance(response, dict):
        return []
    actions = response.get("actions")
    if not isinstance(actions, list):
        return []
    explication = str(response.get("explication") or "").strip()[:300]
    clues: list[dict[str, object]] = []
    for value in actions:
        if not isinstance(value, str):
            continue
        rule = _ACTIONS.get(value)
        if rule is None or not rule[0]:
            continue
        article, strength, statement = rule
        clues.append(
            {
                "clue_code": "ACTION_" + value.upper(),
                "article_code": article,
                "direction": "adverse" if strength >= 50 else "neutral",
                "strength": strength,
                "confidence": 0.8,
                "statement": (statement + " " + explication).strip(),
                "facts": {"requested_action": value, "explication": explication},
            }
        )
    return clues
