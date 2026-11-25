"""La page d'atterrissage qui ne montre rien sans script : une coquille.

Deux faux reçus « Prime » (M-a9e895 le 16 septembre 2026, livré à 0,95 ;
M-373976 le 17) menaient, par leur seul lien d'action, à une page de 484
octets sur un sous-domaine d'hébergement jetable : servie en 200, sans texte,
sans lien, sans formulaire. Tout se joue dans un script que le bac à sable
n'exécute pas. Il l'avait vue et l'avait rendue comme « rien observé » ; le
juge y a lu une absence de charge, alors que le contrôle n'avait rien pu lire.

Ce module dit la différence entre « rien observé » et « rien à voir ». Une
coquille est une page HTML servie normalement, minuscule, vide de tout ce
qu'un lecteur sans script pourrait lire, hors du domaine de l'expéditeur, au
bout d'un lien d'action. Le constat est neutre : une application légitime
rendue par script, une désinscription, un jeu-concours, la page de suivi d'un
routeur d'emailing se présentent pareil. Mesuré sur 60 jours (17 septembre
2026) : 105 indésirables, 2 dangereux, 24 suspects, 8 légitimes. La charge
vient de la convergence (CORR-016) : une finalité de paiement, une première
observation, et cette page-là.

Ce qui n'est pas une coquille : une page lourde dont le bac à sable ne tire
aucun texte (YouTube, Pinterest, une fiche produit : 262 144 octets), le
squelette d'une application qui embarque son amorçage (Salesforce Lightning,
1 845 à 2 883 octets), une feuille de style, un pixel de suivi, un refus (403).
"""

from __future__ import annotations

# Au-delà, la page porte autre chose qu'un chargeur de script : les
# applications légitimes vues en 60 jours commençaient à 1 845 octets, les
# coquilles s'arrêtaient à 698.
TAILLE_MAX = 1024
# Là où le message emmène. La désinscription en pied de page et la navigation
# secondaire ne sont pas l'acte proposé.
_CONTEXTES_D_ACTION = frozenset({"primary"})


def is_opaque_landing(
    *,
    final_status: object,
    content_type: object,
    size: object,
    body_excerpt: object,
    visible_link_count: object,
    form_count: object,
    final_apex: object,
    sender_apex: object,
    link_context: object = None,
) -> bool:
    """La page vue par le bac à sable est-elle une coquille sans script ?

    Toutes les conditions sont nécessaires : servie en 200 (un refus est un
    refus), en HTML (une feuille de style ou une image ne sont pas des pages),
    minuscule, sans texte lisible, sans lien, sans formulaire, hors du domaine
    de l'expéditeur (un site qui sert sa propre application n'emprunte rien),
    au bout d'un lien d'action. Un lien dont le contexte n'a pas été classé
    (``link_context`` absent) reste éligible : seul un contexte qui dit
    « pied de page » ou « navigation secondaire » écarte le lien.
    """
    if not isinstance(final_status, int) or isinstance(final_status, bool):
        return False
    if final_status != 200:
        return False
    if not str(content_type or "").casefold().startswith("text/html"):
        return False
    if not isinstance(size, int) or isinstance(size, bool) or size > TAILLE_MAX:
        return False
    if str(body_excerpt or "").strip():
        return False
    if not isinstance(visible_link_count, int) or visible_link_count != 0:
        return False
    if not isinstance(form_count, int) or form_count != 0:
        return False
    apex = str(final_apex or "").casefold()
    if not apex or apex == str(sender_apex or "").casefold():
        return False
    if link_context is not None and str(link_context) not in _CONTEXTES_D_ACTION:
        return False
    return True
