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
from email.utils import parseaddr

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
# URL_CLOAKING en a été retiré le 29 septembre 2026 : aucun détecteur ne l'a
# jamais émis. Le service conditionnel se dit URL_CONDITIONAL_SERVING
# (DEEP-020), et il peut vivre sur le domaine même de l'expéditeur.
_CROSS_APEX_DESTINATION = frozenset(
    {
        "URL_UNAUTHENTICATED_CROSS_APEX",
        "URL_SANDBOX_CROSS_APEX",
        "URL_CROSS_APEX_FRESH_DESTINATION",
    }
)
_SENSITIVE_FORM = frozenset({"URL_SANDBOX_FORM", "URL_AMBIENT_SENSITIVE_FORM"})
_PROMOTIONAL = frozenset(
    {"NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", "NATURE_SOLICITATION_WITHOUT_OPT_OUT"}
)
_FRESH_OR_DIVERTED = frozenset(
    {"SENDER_DOMAIN_RECENT", "HEADERS_REPLY_TO_DIFFERENT_DOMAIN"}
)
# Une identité empruntée, quelle que soit la façon dont on l'a établie : le
# référentiel de marques d'hier, ou la vérification par recherche qui l'a
# remplacé le 26 août 2026. Sans ce dernier code, une banque imitée depuis un
# domaine étranger ne convergeait plus avec son défaut d'authentification, et
# le juge la posait en question (M-490357, 6 septembre 2026). Le nom affiché
# qui imite par des sosies l'organisation revendiquée en est une aussi : son
# domaine peut être authentique, son nom est emprunté (M-8d026c).
# IDENTITY_COUSIN_DOMAIN est de nouveau produit depuis le 29 septembre 2026,
# par l'enquêteur cousin_domain : l'adresse d'envoi qui se lit comme un
# domaine officiel établi par la recherche. IDENTITY_BRAND_MISMATCH n'est plus
# émis ; il reste lu tant que la rétention garde ses dossiers (2027-02-23).
_BORROWED_IDENTITY = frozenset(
    {
        "IDENTITY_BRAND_MISMATCH",
        "IDENTITY_COUSIN_DOMAIN",
        "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
        "IDENTITY_DISPLAY_NAME_DISGUISED",
    }
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
    # Les indices dont la seule présence défait le faisceau : ils établissent
    # au dossier le contraire de ce qu'un des membres laissait supposer.
    excludes: frozenset[str] = frozenset()

    def matches(self, observed: set[str]) -> list[str]:
        if self.excludes & observed:
            return []
        supporting: list[str] = []
        for family in self.requires:
            found = sorted(family & observed)
            if not found:
                return []
            supporting.extend(found)
        return supporting


CORRELATIONS: tuple[Correlation, ...] = (
    Correlation(
        clue_code="CORRELATION_UNVERIFIED_IDENTITY_DESTINATION",
        article_code="CORR-019", technique_code="FAKE_TRANSACTION_LURE", strength=65,
        statement=(
            "L'identité revendiquée reste non établie et la destination du lien "
            "contredit concrètement l'opération annoncée. L'avis de l'utilisateur "
            "est nécessaire, même si le domaine d'envoi est authentifié."
        ),
        requires=(
            frozenset({"SENDER_WITHOUT_PUBLIC_FOOTPRINT", "SENDER_RELATION_UNVERIFIED"}),
            frozenset({"URL_ACTION_DESTINATION_MISMATCH"}),
        ),
    ),
    Correlation(
        clue_code="CORRELATION_BRAND_SPOOFING",
        article_code="CORR-001",
        technique_code="BRAND_IMPERSONATION",
        strength=80,
        statement=(
            "Le message se présente au nom d’une marque connue alors que son "
            "identité d’envoi n’est pas authentifiée."
        ),
        requires=(_BORROWED_IDENTITY, UNAUTHENTICATED),
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
            _BORROWED_IDENTITY,
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
            "un détournement de son infrastructure est une hypothèse à examiner."
        ),
        # Le montage que rien d'autre ne voit : tout est authentique, sauf le
        # propos. C'est le cas des deux domaines italiens du 16 août.
        # L'authentification est une pièce du faisceau, pas un décor : sans
        # elle, l'énoncé affirmait « s'authentifie correctement » d'un DMARC en
        # échec, et le juge lisait « compte peut-être détourné » là où le
        # dossier montrait une adresse empruntée (M-16ae76, 16 septembre 2026).
        requires=(
            frozenset({"SENDER_ACTIVITY_INCOHERENT"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
            frozenset({"AUTH_DMARC_PASS"}),
        ),
        # Un apex qui a déjà livré chez nous n'est pas un inconnu, quand bien
        # même l'adresse serait inédite : les envoyeurs mutualisés la tirent au
        # hasard à chaque message, si bien que le premier contact y est vrai à
        # perpétuité. Sans cette réserve, ce faisceau n'exigeait plus qu'une
        # seule pièce - l'incohérence d'activité - et portait à 75 ce qu'un
        # unique indice affirmait à 55. C'est ainsi qu'une notification
        # Anthropic authentifiée a été tenue le 1er septembre 2026.
        # Un défaut d'authentification, même à côté d'un DMARC validé, renvoie
        # à la convergence sœur : les deux ne se posent jamais ensemble.
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}) | UNAUTHENTICATED,
    ),
    Correlation(
        clue_code="CORRELATION_SPOOFED_UNRELATED_SENDER",
        article_code="CORR-015",
        technique_code="SENDER_SPOOFING",
        strength=80,
        statement=(
            "L’adresse n’est pas authentifiée et l’activité publiée par son "
            "domaine n’a aucun rapport avec ce message : quelqu’un écrit sous "
            "un nom de domaine qui n’est pas le sien."
        ),
        # La sœur de CORR-007, quand l'authentification manque. Un domaine
        # qui ne reconnaît pas l'envoi et dont le métier est étranger au propos
        # ne décrit pas un compte détourné mais une adresse empruntée : une
        # boutique de vêtements qui annonce un stockage plein (M-16ae76).
        # Mesuré sur 60 jours : 93 messages en première observation, aucun
        # légitime. Sans la première observation, 3 légitimes : on la garde.
        requires=(
            frozenset({"SENDER_ACTIVITY_INCOHERENT"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
            UNAUTHENTICATED,
        ),
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
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
        clue_code="CORRELATION_FAKE_TRANSACTION_LURE",
        article_code="CORR-014",
        technique_code="FAKE_TRANSACTION_LURE",
        strength=55,
        statement=(
            "Le message annonce un paiement, un reçu ou un abonnement depuis un "
            "expéditeur jamais vu dont personne ne répond publiquement : c’est "
            "le leurre de transaction fictive, qui pousse à cliquer pour "
            "« annuler »."
        ),
        # Le faux reçu du 16 septembre 2026 (mozn.space, « Prime Famille »,
        # 69,90 €) : authentifié, structuré, sans pression, et personne
        # derrière le domaine. Aucun des trois faits ne suffit - un vrai reçu
        # PayByPhone est un contexte financier en première observation, et un
        # inconnu sans répondant qui ne parle pas d'argent est un inconnu.
        # Seul « sans répondant » entre ici : une recherche en panne
        # (SENDER_RELATION_UNVERIFIED) n'accuse personne.
        requires=(
            frozenset(
                {
                    "CONTENT_FINANCIAL_CONTEXT",
                    "ACTION_PAYMENT_TRANSFER",
                    "ACTION_BANK_DETAILS_CHANGE",
                }
            ),
            frozenset({"SENDER_WITHOUT_PUBLIC_FOOTPRINT"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
    ),
    Correlation(
        clue_code="CORRELATION_OPAQUE_TRANSACTION_LURE",
        article_code="CORR-016",
        technique_code="FAKE_TRANSACTION_LURE",
        strength=55,
        statement=(
            "Le message annonce un paiement, un reçu ou un abonnement depuis un "
            "expéditeur jamais vu, et son lien d’action mène à une page que le "
            "contrôle ne peut pas lire : c’est le leurre de transaction fictive, "
            "dont la collecte se cache derrière une page vide pour tout lecteur "
            "sans script."
        ),
        # Les deux faux reçus « Prime » des 16 et 17 septembre 2026 : le seul
        # lien d'action menait à une coquille de 484 octets sur un hébergement
        # jetable. La sœur de CORR-014 : là où celle-ci lit le vide autour de
        # l'expéditeur, celle-ci lit le vide au bout du lien. Un vrai reçu en
        # première observation mène à une page qui se lit ; une coquille sans
        # finalité financière est une application ou une désinscription. Sur
        # 60 jours, les trois faits réunis ne touchaient aucun message légitime.
        requires=(
            frozenset(
                {
                    "CONTENT_FINANCIAL_CONTEXT",
                    "ACTION_PAYMENT_TRANSFER",
                    "ACTION_BANK_DETAILS_CHANGE",
                }
            ),
            frozenset({"URL_OPAQUE_LANDING"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
    ),
    Correlation(
        clue_code="CORRELATION_BRAND_TRANSACTION_LURE",
        article_code="CORR-017",
        technique_code="FAKE_TRANSACTION_LURE",
        strength=80,
        statement=(
            "Le message annonce un paiement, un reçu ou un abonnement au nom "
            "d’une marque qu’il emprunte, et c’est la première fois que cet "
            "expéditeur écrit : c’est le leurre de transaction fictive à "
            "l’enseigne d’une marque."
        ),
        # La fausse facture Apple TV du 29 septembre 2026 (M-2a9365, 99 €) :
        # « Support AppIe », un I pour un l, depuis un domaine tiers
        # authentifié et publiquement connu. CORR-014 exigeait un expéditeur
        # sans répondant, CORR-016 une page vide : ni l'un ni l'autre, et le
        # juge a posé la question. Ici c'est l'identité empruntée qui porte
        # le faisceau, quel que soit l'état de l'authentification : une
        # marque ne facture pas sous le nom d'une autre. Sur 60 jours, les
        # trois faits réunis ne touchaient aucun message légitime (une fausse
        # amende ANTAI, un envoi .ru classé indésirable, M-2a9365).
        requires=(
            frozenset(
                {
                    "CONTENT_FINANCIAL_CONTEXT",
                    "ACTION_PAYMENT_TRANSFER",
                    "ACTION_BANK_DETAILS_CHANGE",
                }
            ),
            _BORROWED_IDENTITY,
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
    ),
    Correlation(
        clue_code="CORRELATION_COUSIN_DOMAIN_APPROACH",
        article_code="CORR-004",
        technique_code="COUSIN_DOMAIN",
        strength=80,
        statement=(
            "Le message vient d’une adresse qui imite un domaine officiel par "
            "des caractères sosies, et ce domaine est récent ou renvoie les "
            "réponses ailleurs."
        ),
        # Actif sans producteur du 27 août au 29 septembre 2026 : la table de
        # marques qui posait son indice avait été retirée. L'enquêteur
        # cousin_domain le produit de nouveau, contre les domaines officiels
        # que la recherche a établis. Sur toute la base (49 jours, 4 565
        # messages), aucun message touché, aucun légitime : une protection
        # latente, pas la correction d'un faux négatif connu.
        requires=(frozenset({"IDENTITY_COUSIN_DOMAIN"}), _FRESH_OR_DIVERTED),
    ),
    Correlation(
        clue_code="CORRELATION_UNAUTHENTICATED_PHISHING_HEURISTIC",
        article_code="CORR-018",
        technique_code="URL_OBFUSCATION",
        strength=45,
        statement=(
            "Le filtre antispam soupçonne un hameçonnage, et l’identité de "
            "l’expéditeur n’est pas authentifiée : rien n’établit qui a écrit "
            "ce que le filtre soupçonne."
        ),
        # Une observation, deux sens selon l'authentification, comme la
        # divergence d'un lien entre DEEP-011 et DEEP-010. Sous DMARC validé,
        # le symbole PHISHING de Rspamd est le bruit des campagnes
        # authentifiées (94 messages sur la base, 52 légitimes) et reste
        # neutre. Sans, 3 messages, aucun légitime. Il faut un défaut
        # constaté : un hook d'authentification en erreur n'écrit rien et
        # n'accuse personne. Un DMARC validé l'emporte sur un SPF en échec.
        # Le score agrégé n'y entre pas : il additionne DMARC_POLICY_*,
        # R_SPF_FAIL, VIOLATED_DIRECT_SPF et AUTH_NA_OR_FAIL, déjà comptés
        # par AUTH-002, AUTH-006 et AUTH-008. Force 45, sous le seuil fort, et
        # un faisceau est transverse : ni famille de preuve, ni barrière
        # (heuristic_scores_never_veto tient). La technique est celle du
        # symbole : un lien dont le texte affiche une autre adresse que sa
        # destination.
        requires=(frozenset({"RSPAMD_PHISHING_HEURISTIC"}), UNAUTHENTICATED),
        excludes=frozenset({"AUTH_DMARC_PASS"}),
    ),
    Correlation(
        clue_code="CORRELATION_DISGUISED_UNKNOWN_SENDER",
        article_code="CORR-020",
        technique_code="TEXT_OBFUSCATION",
        strength=75,
        statement=(
            "Le message présente des mots altérés (coupés, cachés ou écrits avec "
            "des lettres sosies) et vient d’un expéditeur jamais vu dont "
            "personne ne répond publiquement."
        ),
        # M-96852d, 30 octobre 2026 : « L'assuranc e vous informe », un objet
        # « Carte A′̍meli », un HTML qui ne rend que « 616 » et un lien, depuis
        # un domaine jetable aux DKIM et SPF valides. La même campagne avait
        # été livrée le 16 octobre (M-7156ca) : 0,92 « légitime » les deux fois.
        # Aucun fait ne suffit seul : un inconnu sans répondant est un inconnu,
        # un texte caché peut être un gabarit. Sur 2 724 messages livrés en 60
        # jours, chacun des trois déguisements ne touche que cette campagne.
        # L'authentification ne défait pas le faisceau : elle prouve qui a
        # écrit, et le domaine jetable signe très bien ses propres envois.
        requires=(
            frozenset(
                {
                    "CONTENT_INTRAWORD_NOISE",
                    "CONTENT_HIDDEN_TEXT_SALTING",
                    "CONTENT_MIXED_SCRIPT",
                }
            ),
            frozenset({"SENDER_WITHOUT_PUBLIC_FOOTPRINT"}),
            frozenset({"HISTORY_FIRST_OBSERVATION"}),
        ),
        excludes=frozenset({"HISTORY_APEX_ESTABLISHED_LOCALLY"}),
    ),
)


def identity_facts(
    from_header: object, envelope_from: object, reply_to: object = None
) -> dict[str, str]:
    """Les identités réellement visibles, sans interpréter le contenu."""
    claimed_name, displayed_email = parseaddr(str(from_header or ""))
    _, technical_email = parseaddr(str(envelope_from or ""))
    _, reply_email = parseaddr(str(reply_to or ""))
    return {
        key: value
        for key, value in {
            "claimed_name": claimed_name.strip(),
            "displayed_email": displayed_email.casefold(),
            "technical_email": technical_email.casefold(),
            "reply_to_email": reply_email.casefold(),
        }.items()
        if value
    }


def _form_on_foreign_destination(
    observed: set[str], evidence: dict[str, dict[str, object]] | None
) -> set[str]:
    """Le formulaire ambiant ne compte que s'il est sur la destination étrangère.

    Ambiant veut dire que le lien qui y mène n'a rien de trompeur. CORR-002 le
    rapprochait d'une redirection prise sur un autre lien : M-d0d979, 9 octobre
    2026, la connexion LinkedIn derrière l'icône d'une lettre d'information,
    les redirections chez son routeur d'envoi. Le lien direct vers un domaine
    récent qui porte lui-même le formulaire reste un faisceau.
    """
    if "URL_AMBIENT_SENSITIVE_FORM" not in observed or evidence is None:
        return observed
    forms = set(_strings(evidence.get("URL_AMBIENT_SENSITIVE_FORM", {}).get("final_apexes")))
    destinations = set(_strings(evidence.get("URL_CROSS_APEX_FRESH_DESTINATION", {}).get("apexes")))
    for code in ("URL_UNAUTHENTICATED_CROSS_APEX", "URL_SANDBOX_CROSS_APEX"):
        for pair in evidence.get(code, {}).get("pairs") or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                destinations.add(str(pair[1]))
    return observed if forms & destinations else observed - {"URL_AMBIENT_SENSITIVE_FORM"}


def _strings(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, (list, tuple)) else []


# Les faisceaux bâtis sur l'incohérence d'activité : ils gardent les identités
# observées et le métier comparé, pour que l'avis montre sur quoi ils reposent.
_ACTIVITY_CORRELATIONS = frozenset(
    {"CORRELATION_COMPROMISED_SENDER", "CORRELATION_SPOOFED_UNRELATED_SENDER"}
)


def correlations(
    observed: set[str],
    *,
    identity: dict[str, str] | None = None,
    evidence: dict[str, dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Les faisceaux réunis par ce message, prêts à devenir des indices."""
    found: list[dict[str, object]] = []
    matchable = _form_on_foreign_destination(observed, evidence)
    for rule in CORRELATIONS:
        supporting = rule.matches(matchable)
        if not supporting:
            continue
        facts: dict[str, object] = {
            "supporting_clue_codes": supporting,
            "attack_technique": rule.technique_code,
        }
        if rule.clue_code in _ACTIVITY_CORRELATIONS and identity:
            facts["identity"] = dict(identity)
        if rule.clue_code in _ACTIVITY_CORRELATIONS and evidence:
            activity = evidence.get("SENDER_ACTIVITY_INCOHERENT")
            if activity:
                facts["activity"] = dict(activity)
        if rule.clue_code == "CORRELATION_UNVERIFIED_IDENTITY_DESTINATION" and evidence:
            facts["destination_contradiction"] = dict(evidence.get("URL_ACTION_DESTINATION_MISMATCH") or {})
        found.append(
            {
                "clue_code": rule.clue_code,
                "article_code": rule.article_code,
                "direction": "adverse",
                "strength": rule.strength,
                "confidence": 0.9,
                "statement": rule.statement,
                "facts": facts,
                "provenance": {"source": "correlation:code"},
            }
        )
    return found
