"""Ce que plusieurs indices disent ensemble, et qu'aucun ne dit seul.

Un nom de marque emprunté n'est rien : une agence cite ses clients. Un DMARC en
échec n'est rien : les configurations sont souvent bancales. Les deux ensemble
décrivent un montage précis, et c'est cette convergence qui informe.

Jusqu'ici le recoupement n'était demandé qu'au modèle, dans son prompt, à chaque
appel et sans filet : rien ne garantissait qu'il le fasse deux fois de la même
façon. Les convergences décrites ici sont calculées, tracées et étiquetées comme
n'importe quel autre indice - elles entrent donc au dossier, au jugement et à
l'apprentissage par la même porte que les autres.

Une convergence ne conclut jamais : elle constate qu'un faisceau est réuni. Le
verdict reste au moteur de jugement.
"""

from __future__ import annotations

from dataclasses import dataclass

# Les défauts d'authentification équivalents : chacun dit, à sa façon, que
# l'identité affichée n'est pas établie.
UNAUTHENTICATED = frozenset(
    {
        "AUTH_DMARC_FAIL",
        "AUTH_DMARC_INCONCLUSIVE",
        "AUTH_SPF_FAIL",
        "AUTH_SPF_SOFTFAIL",
        "AUTH_DKIM_FAIL",
        "AUTH_DKIM_UNALIGNED",
        "AUTH_NO_TRUSTED_RESULTS",
    }
)
_CROSS_APEX_DESTINATION = frozenset(
    {
        "URL_UNAUTHENTICATED_CROSS_APEX",
        "URL_SANDBOX_CROSS_APEX",
        "URL_CROSS_APEX_FRESH_DESTINATION",
        "URL_CLOAKING",
    }
)
_SENSITIVE_FORM = frozenset({"URL_SANDBOX_FORM", "URL_AMBIENT_SENSITIVE_FORM"})
_PROMOTIONAL = frozenset(
    {"NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", "NATURE_SOLICITATION_WITHOUT_OPT_OUT"}
)
_FRESH_OR_DIVERTED = frozenset(
    {"SENDER_DOMAIN_RECENT", "HEADERS_REPLY_TO_DIFFERENT_DOMAIN"}
)


@dataclass(frozen=True)
class Correlation:
    """Un faisceau nommé : ce qu'il exige, ce qu'il constate, ce qu'il enseigne."""

    clue_code: str
    article_code: str
    technique_code: str
    strength: int
    statement: str
    # Chaque entrée est un ensemble d'indices équivalents : la convergence
    # exige au moins un code de chacun.
    requires: tuple[frozenset[str], ...]

    def matches(self, observed: set[str]) -> list[str]:
        supporting: list[str] = []
        for family in self.requires:
            found = sorted(family & observed)
            if not found:
                return []
            supporting.extend(found)
        return supporting


CORRELATIONS: tuple[Correlation, ...] = (
    Correlation(
        clue_code="CORRELATION_BRAND_SPOOFING",
        article_code="CORR-001",
        technique_code="BRAND_IMPERSONATION",
        strength=80,
        statement=(
            "Le message se présente au nom d’une marque connue alors que son "
            "identité d’envoi n’est pas authentifiée."
        ),
        requires=(
            frozenset({"IDENTITY_BRAND_MISMATCH", "IDENTITY_COUSIN_DOMAIN"}),
            UNAUTHENTICATED,
        ),
    ),
    Correlation(
        clue_code="CORRELATION_BRAND_FIRST_CONTACT",
        article_code="CORR-006",
        technique_code="BRAND_IMPERSONATION",
        strength=70,
        statement=(
            "Une marque connue vous écrit pour la première fois depuis un "
            "domaine qui ne lui appartient pas."
        ),
        # Sans défaut d'authentification : l'usurpateur qui enregistre son
        # propre domaine y publie SPF, DKIM et DMARC en règle. Exiger une
        # authentification en défaut revenait à ne voir que les montages
        # bâclés, et à laisser passer les autres.
        requires=(
            frozenset({"IDENTITY_BRAND_MISMATCH", "IDENTITY_COUSIN_DOMAIN"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_COMPROMISED_SENDER",
        article_code="CORR-007",
        technique_code="THREAD_HIJACKING",
        strength=75,
        statement=(
            "L’expéditeur existe et s’authentifie correctement, mais son "
            "activité déclarée n’a aucun rapport avec ce message : "
            "l’infrastructure a vraisemblablement été détournée."
        ),
        # Le montage que rien d'autre ne voit : tout est authentique, sauf le
        # propos. C'est le cas des deux domaines italiens du 16 août.
        requires=(
            frozenset({"SENDER_ACTIVITY_INCOHERENT"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_ANALYSIS_EVASION",
        article_code="CORR-009",
        technique_code="HTML_SMUGGLING",
        strength=80,
        statement=(
            "Une archive protégée par mot de passe accompagne un message qui "
            "invite à l’ouvrir : le chiffrement sert alors à empêcher toute "
            "vérification, pas à protéger un contenu."
        ),
        requires=(
            frozenset({"ATTACHMENT_ENCRYPTED_ARCHIVE"}),
            frozenset({"ACTION_FILE_EXECUTION", "CONTENT_URGENCY"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_MALICIOUS_ATTACHMENT",
        article_code="CORR-010",
        technique_code="MALICIOUS_ATTACHMENT",
        strength=90,
        statement=(
            "Le message porte une pièce jointe capable d’exécuter du code et "
            "invite à l’ouvrir."
        ),
        requires=(
            frozenset(
                {
                    "ATTACHMENT_MACRO_SHELL",
                    "ATTACHMENT_MACRO_AUTO",
                    "ATTACHMENT_ACTIVE_DOCUMENT",
                    "ATTACHMENT_EXECUTABLE_MEMBER",
                    "ATTACHMENT_YARA_MATCH",
                }
            ),
            frozenset({"ACTION_FILE_EXECUTION", "ACTION_SOFTWARE_INSTALL", "CONTENT_URGENCY"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_FINANCIAL_FRAUD",
        article_code="CORR-008",
        technique_code="GIFT_CARD_SCAM",
        strength=85,
        statement=(
            "Le message réclame un acte financier irréversible - virement, "
            "changement de coordonnées bancaires, achat de cartes cadeaux - "
            "alors que l’identité de son expéditeur n’est pas établie."
        ),
        # L'acte le plus coûteux du courrier électronique. Aucun des deux faits
        # ne suffit : une facture authentifiée est ordinaire, et un inconnu qui
        # écrit sans rien demander l'est aussi.
        requires=(
            frozenset(
                {
                    "ACTION_PAYMENT_TRANSFER",
                    "ACTION_BANK_DETAILS_CHANGE",
                    "ACTION_GIFT_CARD_PURCHASE",
                }
            ),
            UNAUTHENTICATED | {"HISTORY_FIRST_OBSERVATION", "SENDER_DOMAIN_RECENT"},
        ),
    ),
    Correlation(
        clue_code="CORRELATION_CREDENTIAL_HARVESTING",
        article_code="CORR-002",
        technique_code="CREDENTIAL_PHISHING_LINK",
        strength=85,
        statement=(
            "Le message conduit à un formulaire de saisie hébergé hors du "
            "domaine de l’expéditeur, dont l’identité n’est pas authentifiée."
        ),
        requires=(_SENSITIVE_FORM, _CROSS_APEX_DESTINATION, UNAUTHENTICATED),
    ),
    Correlation(
        clue_code="CORRELATION_UNSOLICITED_BULK",
        article_code="CORR-003",
        technique_code="GIFT_CARD_SCAM",
        strength=55,
        statement=(
            "Le message est diffusé en copie cachée et tient un discours "
            "promotionnel invérifiable : une prospection non sollicitée."
        ),
        requires=(frozenset({"HEADERS_RECIPIENT_NOT_ADDRESSED"}), _PROMOTIONAL),
    ),
    Correlation(
        clue_code="CORRELATION_PREPARED_APPROACH",
        article_code="CORR-005",
        technique_code="COUSIN_DOMAIN",
        strength=70,
        statement=(
            "Le message vient d’un domaine créé récemment et renvoie les "
            "réponses vers un autre domaine : une approche préparée."
        ),
        requires=(
            frozenset({"SENDER_DOMAIN_RECENT"}),
            frozenset({"HEADERS_REPLY_TO_DIFFERENT_DOMAIN"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_COUSIN_DOMAIN_APPROACH",
        article_code="CORR-004",
        technique_code="COUSIN_DOMAIN",
        strength=80,
        statement=(
            "Le message vient d’un domaine sosie d’une marque connue, créé "
            "récemment ou renvoyant les réponses ailleurs."
        ),
        requires=(frozenset({"IDENTITY_COUSIN_DOMAIN"}), _FRESH_OR_DIVERTED),
    ),
)


def correlations(observed: set[str]) -> list[dict[str, object]]:
    """Les faisceaux réunis par ce message, prêts à devenir des indices."""
    found: list[dict[str, object]] = []
    for rule in CORRELATIONS:
        supporting = rule.matches(observed)
        if not supporting:
            continue
        found.append(
            {
                "clue_code": rule.clue_code,
                "article_code": rule.article_code,
                "direction": "adverse",
                "strength": rule.strength,
                "confidence": 0.9,
                "statement": rule.statement,
                "facts": {
                    "supporting_clue_codes": supporting,
                    "attack_technique": rule.technique_code,
                },
                "provenance": {"source": "correlation:code"},
            }
        )
    return found
