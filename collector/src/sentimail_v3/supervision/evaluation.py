"""Mesurer ce que la chaîne décide, et ce qu'elle se trompe de décider.

Jusqu'ici SentiMail savait dire s'il fonctionnait - files vides, sondes vertes,
aucun message perdu - mais pas s'il avait raison. Le superviseur compte des
défauts d'intégrité, le caretaker liste des désaccords sans dénominateur. Aucun
des deux ne répond à « sur cent messages, combien sont mal traités ».

Ce module ne collecte rien et n'écrit rien : il prend des issues et des
qualifications, et rend des nombres. Les requêtes vivent ailleurs, l'affichage
aussi. Une fonction pure se teste sans base, et se relit.

Quatre partis pris, tirés de ce que la littérature a déjà tranché.

**L'inconnu reste inconnu.** Le scoring crédit a documenté le mode d'échec de
l'imputation : on comble les labels manquants, l'exactitude monte, le rappel
s'effondre, et rien dans le tableau ne le montre. Ici, ce qui n'a pas été
qualifié est compté à part et n'entre dans aucun taux.

**Le risque se normalise par le volume total**, pas par les seuls livrés. Le
risque sélectif - « parmi les livrés, combien étaient indésirables » - baisse
mécaniquement dès qu'on retient davantage, à nombre d'indésirables livrés
identique. Le risque généralisé, lui, mesure ce qui compte : la probabilité
qu'un indésirable atteigne l'utilisateur sans aucun signal.

**Une retenue se compte deux fois.** Demander son avis n'est ni une réussite ni
un échec : c'est un report. Les taux d'erreur sont donc rendus entre deux
bornes, l'une comptant la retenue comme une décision juste, l'autre comme une
erreur. L'écart entre les deux dit exactement quelle part de la performance
repose sur le report à l'humain.

**Les poids du score d'utilité viennent d'un tiers.** Ils sont ceux publiés par
SE Labs pour noter les passerelles de messagerie. Un barème qu'on écrirait
soi-même noterait ce qu'on sait déjà bien faire.

Deux métriques sont volontairement absentes. L'exactitude, parce qu'avec un
courrier légitime à plus de neuf dixièmes, tout livrer affiche un score
flatteur. Le F1, parce qu'il arbitre à poids égal un légitime perdu et un
indésirable livré, ce qui est faux ici.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

DELIVER = "deliver"
ASK = "ask_user"
JUNK = "filed_as_junk"
OUTCOMES: tuple[str, ...] = (DELIVER, ASK, JUNK)

LEGITIMATE = "legitimate"
SPAM = "spam"
# Une réponse en texte libre n'est pas une classe : la verser dans la matrice
# demanderait un arbitrage que personne n'a rendu. Elle est comptée à part, et
# sa croissance signale que la question posée à l'utilisateur est mal formée.
AMBIGUOUS = "ambiguous"
UNKNOWN = "unknown"
TRUTHS: tuple[str, ...] = (LEGITIMATE, SPAM, AMBIGUOUS, UNKNOWN)

# Ce que le message a réellement subi, et ce que cela vaut. Barème SE Labs
# (Advanced Security: Email v2.3), publié pour noter les passerelles de
# messagerie : (poids si le message était indésirable, poids s'il était
# légitime). Retenir protège mieux que classer - la menace est tenue plus loin
# de l'utilisateur - mais coûte plus cher sur un légitime, qu'on dérange.
SE_LABS_WEIGHTS: dict[str, dict[str, int]] = {
    DELIVER: {SPAM: -10, LEGITIMATE: 10},
    ASK: {SPAM: 6, LEGITIMATE: -6},
    JUNK: {SPAM: 5, LEGITIMATE: -5},
}
_MAX_WEIGHT = 10

# logit(0) n'existe pas. Une erreur mesurée nulle sur un petit échantillon ne
# vaut pas zéro, elle vaut « inférieure à ce que l'échantillon peut voir ».
_CONTINUITY = 1e-4


def _truth_of(row: Any) -> str:
    valeur = row.get("truth") if isinstance(row, dict) else None
    if valeur in (LEGITIMATE, SPAM, AMBIGUOUS):
        return str(valeur)
    return UNKNOWN


def _outcome_of(row: Any) -> str:
    valeur = row.get("outcome") if isinstance(row, dict) else None
    if valeur not in OUTCOMES:
        raise ValueError(f"issue inconnue : {valeur!r}")
    return str(valeur)


def confusion_matrix(rows: Iterable[Any]) -> dict[str, Any]:
    """La matrice trois issues sur quatre colonnes, en effectifs bruts.

    La colonne « inconnu » ne se ferme jamais et n'est jamais répartie. Une
    ligne dont la couverture est faible n'est pas une mesure, et la colonne
    « couverture » est là pour l'empêcher d'être lue comme telle.
    """
    lignes: dict[str, dict[str, Any]] = {
        issue: {verite: 0 for verite in TRUTHS} for issue in OUTCOMES
    }
    for row in rows:
        lignes[_outcome_of(row)][_truth_of(row)] += 1
    for issue, ligne in lignes.items():
        total = sum(ligne[verite] for verite in TRUTHS)
        qualifies = ligne[LEGITIMATE] + ligne[SPAM]
        ligne["total"] = total
        ligne["labelled"] = qualifies
        ligne["coverage"] = (qualifies / total) if total else None
    return {"rows": lignes, "total": sum(l["total"] for l in lignes.values())}


def labelling_coverage(rows: Iterable[Any]) -> dict[str, dict[str, Any]]:
    """Sur quelle part de chaque issue on a le droit de conclure.

    Ce n'est pas une performance, c'est une condition de validité. Elle se lit
    avant tout le reste : un taux calculé sur douze messages et un taux calculé
    sur trois mille n'ont pas le même statut, et rien d'autre ne le dit.
    """
    matrice = confusion_matrix(rows)["rows"]
    return {
        issue: {
            "total": ligne["total"],
            "labelled": ligne["labelled"],
            "rate": ligne["coverage"],
        }
        for issue, ligne in matrice.items()
    }


def hold_precision(rows: Iterable[Any]) -> dict[str, Any]:
    """Quand la chaîne dérange l'utilisateur, avait-elle raison de le faire ?

    Le dénominateur ne comprend que les demandes effectivement qualifiées.
    Les demandes sans réponse restent dans le total, sans qualification : la
    couverture et le biais de réponse interdisent d'étendre ce taux à toutes.
    """
    ligne = confusion_matrix(rows)["rows"][ASK]
    qualifies = ligne["labelled"]
    return {
        "value": (ligne[SPAM] / qualifies) if qualifies else None,
        "labelled": qualifies,
        "total": ligne["total"],
        "spam": ligne[SPAM],
        "legitimate": ligne[LEGITIMATE],
    }


def generalized_risk(
    rows: Sequence[Any], *, sampled_delivered: bool = False
) -> dict[str, Any]:
    """La probabilité qu'un indésirable soit livré sans aucun signal.

    Normalisée par le volume total, jamais par les seuls livrés. Sans sondage
    aléatoire des messages livrés, ce nombre n'est qu'une borne inférieure :
    on ne connaît que les indésirables que l'utilisateur a signalés de
    lui-même, et rien ne dit combien sont passés inaperçus. Le drapeau le
    déclare plutôt que de laisser lire un taux pour une mesure.
    """
    matrice = confusion_matrix(rows)
    livres = matrice["rows"][DELIVER]
    total = matrice["total"]
    return {
        "value": (livres[SPAM] / total) if total else None,
        "observed": livres[SPAM],
        "total": total,
        "lower_bound_only": not sampled_delivered,
    }


def trec_rates(rows: Iterable[Any]) -> dict[str, Any]:
    """hm% et sm%, chacun entre deux bornes à cause de la retenue.

    Vocabulaire du TREC Spam Track : hm% est la part du légitime qui n'a pas
    été livrée, sm% la part de l'indésirable qui l'a été. La retenue n'étant ni
    l'un ni l'autre, elle est comptée dans un sens puis dans l'autre. L'écart
    entre les deux bornes mesure ce que la chaîne délègue au lieu de trancher.
    """
    matrice = confusion_matrix(rows)["rows"]
    legitimes = sum(matrice[issue][LEGITIMATE] for issue in OUTCOMES)
    spams = sum(matrice[issue][SPAM] for issue in OUTCOMES)

    def _taux(numerateur: int, denominateur: int) -> float | None:
        return (numerateur / denominateur) if denominateur else None

    return {
        # Optimiste : la retenue est une décision juste.
        "hm_optimistic": _taux(matrice[JUNK][LEGITIMATE], legitimes),
        "sm_optimistic": _taux(matrice[DELIVER][SPAM], spams),
        # Pessimiste : la retenue est une erreur.
        "hm_pessimistic": _taux(
            matrice[JUNK][LEGITIMATE] + matrice[ASK][LEGITIMATE], legitimes
        ),
        "sm_pessimistic": _taux(
            matrice[DELIVER][SPAM] + matrice[ASK][SPAM], spams
        ),
        "legitimate_observed": legitimes,
        "spam_observed": spams,
    }


def lam_percent(hm: float | None, sm: float | None) -> float | None:
    """Les deux erreurs agrégées sans arbitrer entre elles.

    Moyenne des cotes en échelle logistique, telle que définie par le TREC.
    Elle n'impose aucune importance relative entre perdre un légitime et
    livrer un indésirable, et récompense identiquement une amélioration d'un
    même facteur sur l'une ou l'autre - contrairement à une moyenne simple,
    que la plus grande des deux écrase.

    Elle ne se lit pas en langage courant : c'est un chiffre de comparaison
    entre versions, pas un chiffre de rapport.
    """
    if hm is None or sm is None:
        return None

    def _logit(valeur: float) -> float:
        borne = min(max(valeur, _CONTINUITY), 1 - _CONTINUITY)
        return math.log(borne / (1 - borne))

    moyenne = (_logit(hm) + _logit(sm)) / 2
    return 1 / (1 + math.exp(-moyenne))


def utility_score(rows: Iterable[Any]) -> dict[str, Any]:
    """Un chiffre unique, avec des poids que nous n'avons pas choisis.

    Le barème est publié par SE Labs pour noter les passerelles de messagerie.
    Il est rendu avec le score, parce qu'un score dont on cache la pondération
    n'est pas vérifiable - et parce que ces poids sont une opinion défendable,
    pas une vérité : ils supposent qu'une retenue à tort coûte six et non
    soixante, ce qui dépend de ce que le message contenait.
    """
    matrice = confusion_matrix(rows)["rows"]
    total = 0
    comptes = 0
    for issue in OUTCOMES:
        for verite in (SPAM, LEGITIMATE):
            effectif = matrice[issue][verite]
            comptes += effectif
            total += SE_LABS_WEIGHTS[issue][verite] * effectif
    return {
        "raw": total,
        "scored": comptes,
        "normalised": (total / (_MAX_WEIGHT * comptes)) if comptes else None,
        "weights": SE_LABS_WEIGHTS,
    }
