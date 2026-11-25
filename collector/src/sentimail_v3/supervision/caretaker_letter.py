"""Le rapport d'entretien, écrit pour être lu.

Il sortait en JSON brut. Lire « retenues_sans_avis:0 » suppose de savoir ce
qu'est une retenue, et pourquoi zéro est une bonne nouvelle plutôt qu'une
absence de mesure. Un rapport qu'on ne lit pas ne supervise rien : il donne la
sensation d'une surveillance sans en produire l'effet.

Ce module ne mesure rien et ne décide rien. Il traduit un état déjà constaté en
phrases, sans en changer le sens : un compteur à zéro reste visible, un refus
définitif reste un refus. L'état brut ne part pas par courrier : caretaker.run
le journalise intégralement dans audit_log avant l'envoi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape

# Les compteurs qui décrivent une anomalie, du plus grave au plus anodin. Un
# message retenu sans avis est le pire cas du système : il est immobilisé et
# personne ne le sait.
_COMPTEURS: tuple[tuple[str, str, str], ...] = (
    ("retenues_sans_avis", "message retenu sans que son destinataire en soit averti",
     "messages retenus sans que leur destinataire en soit averti"),
    ("dossiers_coinces", "dossier immobilisé depuis plus de 30 minutes",
     "dossiers immobilisés depuis plus de 30 minutes"),
    ("livraisons_differees", "message en attente de livraison",
     "messages en attente de livraison"),
)

# Les quatre sens d'un désaccord. Les deux premiers sont de vraies erreurs : le
# système a tranché, et il a tranché à l'envers. Les deux suivants sont de la
# prudence : il n'a pas su, et il a demandé - c'est le comportement voulu.
# Les avis viennent des destinataires des messages, tous comptes confondus : la
# lettre part à chaque exploitant, qui n'est pas l'auteur de ces jugements.
# Dire « tu as jugé » à l'exploitant lui attribuait les avis des autres.
_ERREURS: tuple[tuple[str, str, str], ...] = (
    ("erreur_de_qualification",
     "j’ai écarté un message que son destinataire a jugé ordinaire",
     "j’ai écarté {n} messages jugés ordinaires par leur destinataire"),
    ("laisse_passer",
     "j’ai livré un message que son destinataire a jugé indésirable",
     "j’ai livré {n} messages jugés indésirables par leur destinataire"),
)
_PRUDENCES: tuple[tuple[str, str, str], ...] = (
    ("demande_au_lieu_de_classer",
     "j’ai demandé son avis au destinataire d’un message qu’il a jugé indésirable",
     "j’ai demandé leur avis aux destinataires de {n} messages qu’ils ont jugés indésirables"),
    ("demande_au_lieu_de_livrer",
     "j’ai demandé son avis au destinataire d’un message ordinaire",
     "j’ai demandé leur avis aux destinataires de {n} messages ordinaires"),
)

_ACTIONS = {
    "replay_errored_verdicts": ("j’ai relancé une analyse en échec",
                                "j’ai relancé {n} analyses en échec"),
    "retry_deferred_deliveries": ("j’ai retenté une livraison",
                                  "j’ai retenté {n} livraisons"),
    "reconcile_review_holds": ("j’ai réconcilié un message retenu",
                               "j’ai réconcilié {n} messages retenus"),
}

_ADRESSE = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")
# Un refus définitif du relais. Le dossier est conclu : la seule « correction »
# imaginable serait de créer la boîte qu'un expéditeur de masse a devinée.
_DEFINITIF = ("5.1.1", "user unknown", "recipient address rejected")

VERT = "#15803d"
ROUGE = "#b91c1c"
AMBRE = "#b45309"
GRIS = "#64748b"
ENCRE = "#0f172a"


@dataclass(frozen=True)
class Lettre:
    subject: str
    text: str
    html: str


def _n(valeur: object) -> int:
    try:
        return int(valeur or 0)
    except (TypeError, ValueError):
        return 0


def _quantite(compte: int, singulier: str, pluriel: str) -> str:
    """Un nombre suivi de ce qu'il compte : « 3 dossiers immobilisés »."""
    return f"{compte} {singulier if compte == 1 else pluriel}"


def _tournure(compte: int, singulier: str, pluriel: str) -> str:
    """Une phrase entière, où le nombre est déjà à sa place.

    Au singulier la phrase se suffit - « j'ai livré un message » - et lui
    préfixer son compte donnerait « 1 j'ai livré un message ».
    """
    return singulier if compte == 1 else pluriel.format(n=compte)


def anomalies(state: dict[str, object]) -> list[str]:
    """Les compteurs non nuls, dits en français, du plus grave au moins."""
    return [
        _quantite(_n(state.get(cle)), singulier, pluriel)
        for cle, singulier, pluriel in _COMPTEURS
        if _n(state.get(cle)) > 0
    ]


def informations(state: dict[str, object]) -> list[str]:
    """Les faits utiles qui n'appellent aucun geste de l'exploitant."""
    amorties = _n(state.get("alertes_amorties_24h"))
    if amorties <= 0:
        return []
    return [
        _quantite(
            amorties,
            "alerte technique a été regroupée pour éviter un courrier répété",
            "alertes techniques ont été regroupées pour éviter des courriers répétés",
        )
        + ". Aucune action n’est requise."
    ]


def lire_refus(entree: dict[str, object]) -> tuple[str, bool]:
    """Traduit une erreur de verdict en phrase, et dit si elle appelle un geste.

    Recopier « SMTPRecipientRefused(550, '5.1.1 … ) » n'apprend rien à qui n'a
    pas le nez dans les codes SMTP, et masque la seule chose qui compte : ce
    refus-là est définitif, il n'y a rien à réparer.
    """
    detail = str(entree.get("detail") or "")
    compte = _n(entree.get("count")) or 1
    fois = "" if compte == 1 else f" ({compte} fois)"
    adresse = _ADRESSE.search(detail)
    if any(marque in detail.casefold() for marque in _DEFINITIF):
        cible = adresse.group(1) if adresse else "cette adresse"
        return (
            f"La boîte {cible} n’existe pas{fois}. Le refus du serveur est "
            "définitif : le dossier est conclu, il n’y a rien à réparer.",
            False,
        )
    genre = str(entree.get("error_type") or "erreur inconnue")
    return (f"Une analyse a échoué sur « {genre} »{fois}.", True)


def _sens(state: dict[str, object]) -> tuple[list[str], list[str]]:
    lecture = state.get("sens_des_desaccords_7j")
    lecture = lecture if isinstance(lecture, dict) else {}
    erreurs = [
        _tournure(_n(lecture.get(cle)), singulier, pluriel).capitalize()
        for cle, singulier, pluriel in _ERREURS
        if _n(lecture.get(cle)) > 0
    ]
    prudences = [
        _tournure(_n(lecture.get(cle)), singulier, pluriel).capitalize()
        for cle, singulier, pluriel in _PRUDENCES
        if _n(lecture.get(cle)) > 0
    ]
    return erreurs, prudences


def _actions(outcome: dict[str, object]) -> list[str]:
    faites = []
    for action, compte in (outcome or {}).items():
        nombre = _n(compte)
        if nombre <= 0:
            continue
        singulier, pluriel = _ACTIONS.get(
            str(action), (f"j’ai exécuté « {action} »", f"j’ai exécuté « {action} » {{n}} fois")
        )
        faites.append(_tournure(nombre, singulier, pluriel).capitalize())
    return faites


def actions_requises(
    state: dict[str, object], outcome: dict[str, object]
) -> list[str]:
    """Ce que le lecteur peut réellement faire après les réparations automatiques."""
    # Un désaccord humain/modèle n'appelle aucun geste : le verdict humain
    # s'est appliqué et personne ne repasse derrière (13 septembre 2026).
    required: list[str] = []

    rejouees = _n(outcome.get("replay_errored_verdicts"))
    reparables = sum(
        _n(entry.get("count")) or 1
        for entry in (state.get("erreurs_de_verdict_24h") or [])
        if isinstance(entry, dict) and lire_refus(entry)[1]
    )
    if reparables > rejouees:
        required.append(
            "Une analyse reste en échec après la tentative automatique : "
            "ouvre son dossier dans la console."
        )
    if _n(state.get("retenues_sans_avis")) > _n(
        outcome.get("reconcile_review_holds")
    ):
        required.append(
            "Un message reste retenu sans avis : vérifie le pipeline et son dossier."
        )
    if _n(state.get("dossiers_coinces")) > 0:
        required.append(
            "Un dossier reste immobilisé depuis plus de 30 minutes : ouvre-le "
            "dans la console."
        )
    if _n(state.get("livraisons_differees")) > _n(
        outcome.get("retry_deferred_deliveries")
    ):
        required.append(
            "Une livraison reste différée après la tentative automatique : "
            "vérifie son dossier."
        )
    return required


def _sujet(
    state: dict[str, object],
    erreurs: list[str],
    prudences: list[str],
    refus: list[tuple[str, bool]],
    required: list[str],
) -> str:
    """L'objet dit la situation et son niveau, en cohérence avec l'en-tête.

    Trois niveaux : grave quand le système s'est trompé ou qu'un compteur
    d'anomalie est levé ; modéré quand des analyses en échec appellent une
    réparation ; faible quand la lettre ne porte que des faits qui ne
    demandent rien - refus définitifs, désaccords de prudence. Sans rien de
    tout cela, il n'y a rien à signaler.
    """
    points = anomalies(state)
    if required and points:
        return (
            "[SentiMail] Entretien : signalement grave, intervention requise - "
            + points[0]
        )
    if required:
        return (
            "[SentiMail] Entretien : signalement modéré, intervention requise - "
            "une analyse ou un écart est à examiner"
        )
    if erreurs or refus or prudences:
        return (
            "[SentiMail] Entretien : signalement faible - "
            "des faits notés, aucune action requise"
        )
    return "[SentiMail] Entretien : rien à signaler"


def lettre(
    state: dict[str, object],
    verdict: dict[str, object],
    outcome: dict[str, object],
    ecarts_url: str | None = None,
) -> Lettre:
    """Compose le rapport d'entretien, en texte et en page."""
    points = anomalies(state)
    erreurs, prudences = _sens(state)
    refus = [
        lire_refus(entree)
        for entree in (state.get("erreurs_de_verdict_24h") or [])
        if isinstance(entree, dict)
    ]
    faites = _actions(outcome)
    required = actions_requises(state, outcome)
    infos = informations(state)
    diagnostic = str(verdict.get("diagnosis") or "").strip()
    note = str(verdict.get("operator_note") or "").strip()
    ignorees = [str(x) for x in (verdict.get("ignored_recommendations") or [])]

    if required:
        entete = "Ton intervention est requise."
        couleur = ROUGE if erreurs else AMBRE
    elif erreurs:
        entete = (
            "Un destinataire a corrigé mon jugement : sa décision s’applique, "
            "aucune action n’est requise."
        )
        couleur = ROUGE
    else:
        entete = "Aucune action n’est requise."
        couleur = VERT

    # ── texte ────────────────────────────────────────────────────────────
    lignes = [entete, ""]
    if required:
        lignes += ["Ce que tu dois faire :"]
        lignes += [f"  - {item}" for item in required]
        lignes += [""]
    else:
        lignes += ["Ce que tu dois faire :", "  - Rien.", ""]
    if points:
        lignes += ["Ce qui n’est pas normal :"]
        lignes += [f"  - {point}." for point in points]
        lignes += [""]
    else:
        lignes += [
            "Aucun message n’est immobilisé, aucun n’est retenu sans que son "
            "destinataire en soit averti et aucune livraison n’attend.",
            "",
        ]
    if infos:
        lignes += ["Informations, sans action requise :"]
        lignes += [f"  - {item}" for item in infos]
        lignes += [""]
    if refus:
        lignes += ["Les analyses qui n’ont pas abouti :"]
        lignes += [f"  - {phrase}" for phrase, _ in refus]
        lignes += [""]
    if erreurs or prudences:
        lignes += ["Là où l’avis des destinataires a différé du mien, ces sept derniers jours :"]
        if erreurs:
            lignes += [f"  - {phrase}. C’est une erreur de ma part." for phrase in erreurs]
        else:
            lignes += ["  - Aucune erreur de jugement : je n’ai ni écarté un "
                       "message ordinaire, ni livré un indésirable."]
        for phrase in prudences:
            lignes += [f"  - {phrase}. Là je n’ai pas tranché, j’ai demandé - "
                       "c’est le comportement voulu."]
        lignes += [""]
    if diagnostic:
        lignes += ["Ce que j’en comprends :", diagnostic, ""]
    if faites:
        lignes += ["Ce que j’ai fait :"] + [f"  - {phrase}." for phrase in faites] + [""]
    else:
        lignes += ["Je n’ai rien eu à faire : aucune action n’était justifiée.", ""]
    if ignorees:
        lignes += [
            "Écartées parce qu’elles sortent de ce que j’ai le droit de faire "
            "seul : " + ", ".join(ignorees),
            "",
        ]
    if note:
        lignes += ["Pour toi :", note, ""]
    if ecarts_url:
        lignes += [
            f"Voir les écarts, déjà tranchés par les destinataires : {ecarts_url}",
            "",
        ]
    # L'état brut ne part plus par courrier : caretaker.run le journalise
    # intégralement dans audit_log avant l'envoi, et personne ne lit trente
    # compteurs dans un email. Le courrier reste entièrement rédigé.
    lignes += ["— L’agent d’entretien de MAIA, SentiMail V3"]

    # ── page ─────────────────────────────────────────────────────────────
    def bloc(titre: str, items: list[str], teinte: str = ENCRE) -> str:
        if not items:
            return ""
        puces = "".join(
            f'<li style="margin:0 0 6px 0;line-height:1.4">{escape(x)}</li>'
            for x in items
        )
        return (
            '<div style="margin-top:14px">'
            f'<div style="font-size:13px;font-weight:bold;color:{teinte};'
            f'margin-bottom:6px">{escape(titre)}</div>'
            f'<ul style="margin:0;padding-left:18px;font-size:14px;color:{ENCRE}">'
            f"{puces}</ul></div>"
        )

    corps = [
        f'<div style="background:{couleur};color:#ffffff;padding:12px 14px;'
        'border-radius:10px;font-size:14px;font-weight:bold">'
        f"{escape(entete)}</div>"
    ]
    corps.append(
        bloc(
            "Ce que tu dois faire",
            required or ["Rien."],
            ROUGE if required else VERT,
        )
    )
    if points:
        corps.append(bloc("Ce qui n’est pas normal", [f"{p}." for p in points], AMBRE))
    else:
        corps.append(
            f'<div style="margin-top:14px;font-size:14px;color:{ENCRE};'
            'line-height:1.45">Aucun message n’est immobilisé, aucun n’est '
            "retenu sans que son destinataire en soit averti, aucune livraison "
            "n’attend.</div>"
        )
    corps.append(bloc("Informations, sans action requise", infos, GRIS))
    corps.append(bloc("Les analyses qui n’ont pas abouti", [p for p, _ in refus], GRIS))
    if erreurs or prudences:
        detail = [f"{p}. C’est une erreur de ma part." for p in erreurs] or [
            "Aucune erreur de jugement : je n’ai ni écarté un message "
            "ordinaire, ni livré un indésirable."
        ]
        detail += [
            f"{p}. Là je n’ai pas tranché, j’ai demandé - c’est le comportement voulu."
            for p in prudences
        ]
        corps.append(
            bloc("Là où l’avis des destinataires a différé du mien, ces sept derniers jours",
                 detail, ROUGE if erreurs else VERT)
        )
    if diagnostic:
        corps.append(
            '<div style="margin-top:14px;padding:11px 13px;background:#f8fafc;'
            'border-left:4px solid #cbd5e1;border-radius:8px;font-size:14px;'
            f'color:{ENCRE};line-height:1.45">'
            f'<div style="font-weight:bold;margin-bottom:4px">Ce que j’en '
            f"comprends</div>{escape(diagnostic)}</div>"
        )
    corps.append(
        bloc("Ce que j’ai fait", [f"{p}." for p in faites], VERT)
        or f'<div style="margin-top:14px;font-size:14px;color:{GRIS}">'
        "Je n’ai rien eu à faire : aucune action n’était justifiée.</div>"
    )
    corps.append(bloc("Écartées, hors de ce que je fais seul", ignorees, GRIS))
    if note:
        corps.append(bloc("Pour toi", [note], ENCRE))
    if ecarts_url:
        corps.append(
            f'<div style="margin-top:14px;font-size:14px;color:{ENCRE}">'
            f'<a href="{escape(ecarts_url)}" style="color:#1a5fd0">'
            "Voir les écarts, déjà tranchés par les destinataires</a></div>"
        )
    corps.append(
        '<div style="margin-top:14px;font-size:12px;color:#475569">'
        "— L’agent d’entretien de MAIA, SentiMail V3</div>"
    )

    html = (
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        f'margin:0 auto;color:{ENCRE}">' + "".join(corps) + "</div>"
    )
    return Lettre(
        _sujet(state, erreurs, prudences, refus, required),
        "\n".join(lignes),
        html,
    )
