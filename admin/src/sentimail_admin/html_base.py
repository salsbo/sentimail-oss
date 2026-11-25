"""Socle HTML partagé par les pages de la console.

Feuille de style embarquée, navigation, messages d'état sur liste fermée,
gabarit de document et formateurs communs. Pas de moteur de rendu, pas de
JavaScript, pas de ressource distante.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from html import escape
from typing import Any
from urllib.parse import quote

STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
       background: #f6f7f9; color: #1a1d21; }
header { background: #14171a; color: #f6f7f9; padding: 1rem 1.5rem; }
header h1 { margin: 0 0 .6rem; font-size: 1.1rem; font-weight: 600;
            letter-spacing: .02em; }
nav a { color: #cfd6dd; text-decoration: none; margin-right: 1.2rem;
        font-size: .95rem; }
nav a.actif { color: #fff; border-bottom: 2px solid #4c9aff; padding-bottom: 2px; }
main { max-width: 76rem; margin: 0 auto; padding: 1.5rem; }
h2 { font-size: 1.25rem; margin: 0 0 .3rem; }
p.chapeau { margin: 0 0 1.2rem; color: #5a6470; }
section { background: #fff; border: 1px solid #e2e6ea; border-radius: 8px;
          padding: 1.2rem; margin-bottom: 1.5rem; }
/* Une adresse électronique ou un domaine est un mot sans espace : sans cette
   règle, la largeur minimale d'une colonne devenait celle du plus long, la
   table dépassait sa section et la page défilait latéralement. */
table { width: 100%; border-collapse: collapse; font-size: .93rem;
        table-layout: fixed; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #eceff2;
         vertical-align: top; overflow-wrap: anywhere; }
th { color: #5a6470; font-weight: 600; font-size: .82rem;
     text-transform: uppercase; letter-spacing: .04em; }
td.compact { white-space: nowrap; color: #5a6470; }
/* Ce qui accompagne la valeur principale d'une cellule sans la concurrencer :
   le rDNS sous une adresse, par exemple. */
.secondaire { margin-top: .2rem; font-size: .85em; color: #5a6470; }
td.elements { padding-top: 0; }
td.elements summary { cursor: pointer; color: #5a6470; font-size: .85rem; }
td.elements p, td.elements ul { margin: .5rem 0 0 0; font-size: .9rem; }
td.elements ul { padding-left: 1.2rem; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
  font-size: 0.82em; white-space: nowrap; }
/* Dans une table à colonnes fixes, un badge qui ne se coupe jamais déborde
   sur la colonne voisine : il s'y replie. */
td .badge { white-space: normal; }
.badge-vert { background: #e7f5ec; color: #14532d; }
.badge-ambre { background: #fdf1e3; color: #7c2d12; }
.badge-gris { background: #eef1f4; color: #47505a; }
form.recherche { margin: 0 0 12px 0; display: flex; gap: 8px; }
form.recherche input { flex: 1; max-width: 380px; }
form.aller { display: flex; gap: .4rem; align-items: center; margin-top: .7rem; }
form.aller label { margin: 0; color: #9aa4ae; font-size: .8rem;
        text-transform: uppercase; letter-spacing: .04em; }
form.aller input { width: 12rem; padding: .3rem .5rem; font: inherit;
        font-size: .88rem; border-radius: 6px; border: 1px solid #39414a;
        background: #1c2126; color: #e7eaee; }
form.aller button { padding: .3rem .7rem; font-size: .88rem;
        background: #262c33; color: #e7eaee; border-color: #39414a; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
       font-size: .88em; background: #f0f2f5; padding: .1rem .3rem;
       border-radius: 4px; overflow-wrap: anywhere; }
/* Une adresse IP, une plage, une référence : ça se lit d'un bloc ou pas du
   tout. « 93.184.216.99/32 » coupé en trois lignes n'est plus une adresse. */
code.insecable { white-space: nowrap; overflow-wrap: normal; }
/* Un jeton de vérification, lui, n'a pas de sens de lecture : il se coupe. */
code.jeton { word-break: break-all; }
.etat { display: inline-block; padding: .1rem .55rem; border-radius: 999px;
        font-size: .8rem; font-weight: 600; }
.etat-actif, .etat-ok, .etat-delivered { background: #e3f5e9; color: #17692f; }
.etat-attente, .etat-degraded, .etat-held { background: #fdf1dc; color: #8a5a08; }
.etat-suspendu, .etat-down { background: #fbe4e4; color: #8f2020; }
.etat-neutre { background: #eceff2; color: #4a545f; }
form.enligne { display: inline; }
label { display: block; font-size: .85rem; color: #5a6470; margin-bottom: .2rem; }
input[type=text], input[type=email] { width: 100%; padding: .5rem .6rem;
       border: 1px solid #cfd6dd; border-radius: 6px; font: inherit; }
.champs { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: .9rem; }
.champs > div { flex: 1 1 16rem; }
.classifier-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin: 1rem 0; }
.classifier-stats strong { display: block; font-size: 1.8rem; }
button { font: inherit; padding: .45rem .9rem; border-radius: 6px;
         border: 1px solid #cfd6dd; background: #fff; cursor: pointer; }
button.principal { background: #1a5fd0; border-color: #1a5fd0; color: #fff; }
button.discret { color: #8f2020; }
.avis { padding: .7rem 1rem; border-radius: 6px; margin-bottom: 1.2rem;
        font-size: .93rem; }
.avis-ok { background: #e3f5e9; color: #17692f; }
.avis-erreur { background: #fbe4e4; color: #8f2020; }
.vide { color: #5a6470; font-style: italic; }
footer { max-width: 76rem; margin: 0 auto; padding: 0 1.5rem 2rem;
         color: #7a838d; font-size: .82rem; }
@media (prefers-color-scheme: dark) {
  body { background: #14171a; color: #e7eaee; }
  section { background: #1c2126; border-color: #2c333a; }
  th, td { border-color: #2c333a; }
  code { background: #262c33; }
  input[type=text], input[type=email] { background: #14171a; color: #e7eaee;
        border-color: #39414a; }
  button { background: #262c33; color: #e7eaee; border-color: #39414a; }
  button.principal { background: #1a5fd0; border-color: #1a5fd0; }
  p.chapeau, .vide, td.compact, .secondaire, footer { color: #9aa4ae; }
}
"""

ONGLETS: tuple[tuple[str, str], ...] = (
    ("/domaines", "Domaines"),
    ("/etat", "État du système"),
    ("/courrier", "Courrier récent"),
    ("/mesure", "Mesure d'efficacité"),
    ("/ecarts", "Écarts"),
    ("/apprentissage", "Registre d'apprentissage"),
    ("/classifieur", "Classifieur local"),
    ("/sources", "Sources hostiles"),
    ("/reglages", "Réglages"),
)

# Les avis affichés après une modification. Liste fermée : l'URL choisit une
# clé, jamais un texte, donc rien de ce qui vient du réseau n'est réaffiché.
AVIS: Mapping[str, tuple[str, str]] = {
    "plafonds_enregistres": ("ok", "Plafonds enregistrés pour ce domaine."),
    "moteur_enregistre": (
        "ok",
        "Clé posée sur le serveur. Elle n'a traversé aucune boîte aux "
        "lettres et n'est enregistrée nulle part ailleurs.",
    ),
    "modele_enregistre": (
        "ok",
        "Rôle confié au modèle local. Éprouve-le avant de compter dessus.",
    ),
    "modele_retire": ("ok", "Rôle rendu au fournisseur distant."),
    "identite_enregistree": (
        "ok",
        "Identité de l'instance enregistrée. Elle prime désormais sur "
        "l'environnement du service.",
    ),
    "domaine_ajoute": ("ok", "Domaine ajouté. Publiez son jeton avant de l'activer."),
    "client_ajoute": ("ok", "Client ajouté. Vous pouvez maintenant y rattacher ses domaines."),
    "client_existant": ("erreur", "Ce client existe déjà."),
    "domaine_rattache": ("ok", "Domaine rattaché. Les retours s'appliquent désormais à tout ce client."),
    "ecart_traite": ("ok", "Écart marqué traité. Il reste compté dans les mesures."),
    "ecart_inconnu": ("erreur", "Cet écart n'existe pas ou est déjà traité."),
    "reference_illisible": (
        "erreur",
        "Ce n'est pas une référence de dossier. Une référence s'écrit "
        "« E-c62805 » pour un écart, « M-e9e8f2 » pour un message.",
    ),
    "reference_courrier": (
        "erreur",
        "« D-… » est la référence d'un récapitulatif envoyé par courrier. "
        "Elle situe des numéros dans cette lettre ; elle ne désigne aucun "
        "dossier de la console.",
    ),
    "source_ajoutee": ("ok", "Source ajoutée au registre. Le MX la refusera d'ici une minute."),
    "source_supprimee": ("ok", "Source retirée du registre."),
    "source_existante": ("erreur", "Cette source figure déjà au registre."),
    "source_inconnue": ("erreur", "Cette source ne figure pas au registre."),
    "domaine_existant": ("erreur", "Ce domaine est déjà enregistré."),
    "domaine_active": ("ok", "Domaine activé. La prise en compte demande 30 secondes."),
    "domaine_suspendu": (
        "ok",
        "Domaine suspendu. Ses destinataires ne sont plus pris en charge.",
    ),
    "domaine_inconnu": ("erreur", "Ce domaine n'existe plus."),
    "domaine_non_verifie": (
        "erreur",
        (
            "Ce domaine n'a pas encore prouvé sa maîtrise : publie le jeton en "
            "TXT sur _sentimail.<domaine>, fais vérifier, puis active."
        ),
    ),
}

ETATS_LIVRAISON: Mapping[str, str] = {
    "captured": "reçu",
    "analyzing": "en analyse",
    "held": "retenu",
    "release_pending": "libération en cours",
    "deferred": "différé",
    "delivered": "livré",
    "consumed": "traité",
    "undeliverable": "destinataire inexistant",
}

ETATS_COMPOSANT: Mapping[str, str] = {
    "ok": "opérationnel",
    "degraded": "dégradé",
    "down": "hors service",
}

ETATS_DOMAINE: Mapping[str, str] = {
    "pending": "en attente",
    "active": "actif",
    "suspended": "suspendu",
}

_CLASSES_ETAT: Mapping[str, str] = {
    "active": "etat-actif",
    "pending": "etat-attente",
    "suspended": "etat-suspendu",
    "ok": "etat-ok",
    "degraded": "etat-degraded",
    "down": "etat-down",
    "delivered": "etat-delivered",
    "held": "etat-held",
}


def _classe(valeur: str) -> str:
    return _CLASSES_ETAT.get(valeur, "etat-neutre")


def pastille(valeur: str | None, libelles: Mapping[str, str]) -> str:
    brut = str(valeur or "")
    texte_libelle = libelles.get(brut, brut or "-")
    return f'<span class="etat {_classe(brut)}">{escape(texte_libelle)}</span>'


def horodatage(value: Any) -> str:
    if not isinstance(value, datetime):
        return "-"
    return escape(value.astimezone(timezone.utc).strftime("%d/%m/%Y %H:%M"))


def colonnes(*largeurs: str) -> str:
    """La largeur de chaque colonne, déclarée avant la première ligne.

    Les tables sont en ``table-layout: fixed`` : sans ce partage, toutes les
    colonnes seraient égales, et un objet de courrier recevrait la même place
    qu'un badge de trois lettres. Avec, la répartition est celle qu'on a
    voulue, et le contenu s'y plie au lieu d'élargir la page.
    """
    return (
        "<colgroup>"
        + "".join(f'<col style="width:{largeur}">' for largeur in largeurs)
        + "</colgroup>"
    )


def texte(value: Any, *, defaut: str = "-", maximum: int = 160) -> str:
    brut = "" if value is None else str(value)
    brut = brut.replace("\r", " ").replace("\n", " ").strip()
    if not brut:
        return escape(defaut)
    if len(brut) > maximum:
        brut = brut[: maximum - 1] + "…"
    return escape(brut)


def _url(valeur: Any) -> str:
    return escape(quote(str(valeur), safe=""))


def _pourcentage(valeur: Any, *, defaut: str = "-") -> str:
    if not isinstance(valeur, (int, float)) or isinstance(valeur, bool):
        return defaut
    return f"{valeur * 100:.1f} %"


def _entier(valeur: Any) -> str:
    return str(valeur) if isinstance(valeur, int) and not isinstance(valeur, bool) else "-"


def _date_mesure(value: Any) -> str:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return "-"
    return horodatage(value)


def document(titre: str, chemin_actif: str, corps: str, avis: str | None = None) -> str:
    onglets = "".join(
        f'<a href="{chemin}"'
        + (' class="actif"' if chemin == chemin_actif else "")
        + f">{escape(libelle)}</a>"
        for chemin, libelle in ONGLETS
    )
    bandeau = ""
    if avis and avis in AVIS:
        ton, message = AVIS[avis]
        bandeau = f'<p class="avis avis-{ton}">{escape(message)}</p>'
    return (
        "<!DOCTYPE html>\n"
        '<html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{escape(titre)} - SentiMail</title>"
        f"<style>{STYLE}</style></head><body>"
        "<header><h1>SentiMail - configuration</h1>"
        f"<nav>{onglets}</nav>"
        # Le champ qui ouvre un dossier cité. Il est dans le bandeau parce
        # qu'une référence se colle d'où qu'on vienne : depuis un échange,
        # depuis un avis, depuis une note - jamais depuis la page qui la
        # portait déjà.
        '<form method="get" action="/aller" class="aller">'
        '<label for="ref">Aller au dossier</label>'
        '<input type="search" id="ref" name="ref" placeholder="E-c62805, M-e9e8f2…" '
        'autocomplete="off" spellcheck="false">'
        '<button type="submit">Ouvrir</button></form>'
        "</header>"
        f"<main>{bandeau}{corps}</main>"
        "<footer>Accès réservé au tailnet. Chaque modification est enregistrée "
        "avec l'adresse qui l'a demandée.</footer>"
        "</body></html>"
    )


def page_erreur(titre: str, message: str) -> str:
    corps = (
        f"<section><h2>{escape(titre)}</h2>"
        f'<p class="avis avis-erreur">{escape(message)}</p>'
        '<p><a href="/domaines">Revenir aux domaines</a></p></section>'
    )
    return document(titre, "", corps)
