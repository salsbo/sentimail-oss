"""Qui a le droit de répondre à un avis, et depuis quelle adresse.

Le jeton d'un avis prouve qu'on a lu la boîte à laquelle il a été envoyé.
L'adresse d'expédition, elle, prouve peu de chose : un logiciel de messagerie
qui agrège plusieurs comptes signe avec l'identité par défaut, et la réponse
part alors d'une autre adresse que celle de l'avis. Jetée, elle emportait la
seule vérité dont dispose SentiMail - la décision humaine.

Une adresse inconnue ne décide donc plus rien tout de suite, mais elle n'est
plus perdue : MAIA envoie un code à la boîte de l'avis. Qui la lit ouvre
l'alias, une fois, pour toujours ; qui a seulement reçu l'avis en transfert ne
le peut pas. La réponse mise de côté est appliquée à la confirmation.
"""

from __future__ import annotations

# Le motif de l'action de confirmation. Il la distingue d'une authentification
# de directive libre, qui challenge l'expéditeur lui-même et non la boîte.
ALIAS_PURPOSE = "confirm_reply_alias"

# Un code de directive vaut cinq minutes : la directive vient d'être écrite, et
# son auteur attend devant sa boîte. Reconnaître une adresse ne se passe pas
# ainsi - le courrier arrive au milieu d'une journée, dans la boîte que l'on ne
# consulte justement pas en premier. Cinq minutes rendraient le geste
# impossible, et une seule tentative est admise : un code de six caractères ne
# se devine pas en un essai.
ALIAS_TTL_MINUTES = 24 * 60


def alias_decision(same_mailbox: bool, alias_confirmed: bool) -> str:
    """Ce qu'il advient d'une réponse selon l'adresse qui l'envoie.

    `accept` : elle vient de la boîte de l'avis. `accepted_alias` : d'une
    adresse déjà confirmée pour cette personne - une fois suffit, c'est ce qui
    rend le réglage durable. `challenge` : d'une adresse inconnue, qui devra
    prouver l'accès à la boîte avant que sa réponse compte.
    """
    if same_mailbox:
        return "accept"
    return "accepted_alias" if alias_confirmed else "challenge"


def alias_challenge_letter(alias: str, expected: str, code: str) -> tuple[str, str]:
    """Le courrier envoyé à la boîte de l'avis pour ouvrir une adresse.

    Il part vers `expected`, jamais vers `alias` : c'est tout le mécanisme.
    Écrire à l'adresse à valider reviendrait à lui demander de se valider
    elle-même.
    """
    subject = "[SentiMail] Confirme ton adresse de réponse à MAIA"
    body = (
        f"Tu as répondu à un de mes avis depuis {alias}, alors que je l’avais "
        f"envoyé à {expected}.\n\n"
        "Je garde ta réponse de côté : elle sera prise en compte dès que tu "
        "auras confirmé que cette adresse est bien la tienne.\n\n"
        f"Réponds exactement : CONFIRME MAIA {code}\n\n"
        "Ce code vaut 24 heures. Tu n’auras à le faire qu’une seule fois : "
        "ensuite, tes réponses depuis cette adresse compteront directement.\n\n"
        "Si tu n’as rien envoyé, ignore cet email : sans confirmation, rien "
        "de ce qui a été demandé depuis cette adresse ne sera appliqué.\n\n"
        "— MAIA, ton assistante SentiMail"
    )
    return subject, body
