"""Les pages, écrites à la main.

Pas de moteur de rendu, pas de JavaScript, pas de ressource distante : la page
doit s'afficher entière sur une machine hors ligne, et son style tient dans
l'en-tête. Toute valeur venant de la base traverse ``escape`` ; les messages
d'état ne sont jamais réfléchis depuis l'URL, seulement choisis dans une liste
fermée.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from html import escape
from typing import Any

from .naming import verification_record
from .reference import reference
from .presets import PRESETS

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
    texte = libelles.get(brut, brut or "-")
    return f'<span class="etat {_classe(brut)}">{escape(texte)}</span>'


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


# --- Domaines ---------------------------------------------------------------


def page_domaines(domaines: Sequence[Mapping[str, Any]]) -> str:
    if domaines:
        lignes = "".join(_ligne_domaine(domaine) for domaine in domaines)
        tableau = (
            "<table><thead><tr><th>Domaine</th><th>État</th><th>Contact</th>"
            "<th>Jeton à publier</th><th>Vérifié le</th><th></th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    else:
        tableau = '<p class="vide">Aucun domaine enregistré pour le moment.</p>'

    return (
        "<section><h2>Domaines protégés</h2>"
        '<p class="chapeau">Un domaine actif protège tous ses destinataires. '
        "L'activation est prise en compte en moins de trente secondes par les "
        "autres services.</p>"
        f"{tableau}</section>"
        "<section><h2>Ajouter un domaine</h2>"
        '<p class="chapeau">Le domaine est créé en attente. Publiez son jeton en '
        "TXT, puis activez-le.</p>"
        '<form method="post" action="/domaines/ajouter">'
        '<div class="champs">'
        '<div><label for="fqdn">Domaine</label>'
        '<input type="text" id="fqdn" name="fqdn" placeholder="exemple.fr" '
        'autocomplete="off" required></div>'
        '<div><label for="admin_email">Contact (facultatif)</label>'
        '<input type="email" id="admin_email" name="admin_email" '
        'placeholder="admin@exemple.fr" autocomplete="off"></div>'
        "</div>"
        '<button type="submit" class="principal">Ajouter</button>'
        "</form></section>"
    )


def _ligne_domaine(domaine: Mapping[str, Any]) -> str:
    fqdn = str(domaine["fqdn"])
    identifiant = escape(str(domaine["id"]))
    statut = str(domaine["status"])
    if statut == "active":
        action = (
            f'<form method="post" action="/domaines/suspendre" class="enligne">'
            f'<input type="hidden" name="domaine" value="{identifiant}">'
            f'<button type="submit" class="discret">Suspendre</button></form>'
        )
    else:
        action = (
            f'<form method="post" action="/domaines/activer" class="enligne">'
            f'<input type="hidden" name="domaine" value="{identifiant}">'
            f'<button type="submit" class="principal">Activer</button></form>'
        )
    jeton = (
        f"<code>{escape(verification_record(fqdn))}</code><br>"
        f'<code class="jeton">{texte(domaine["verification_token"], maximum=80)}</code>' 
    )
    return (
        f"<tr><td><strong>{texte(fqdn)}</strong></td>"
        f"<td>{pastille(statut, ETATS_DOMAINE)}</td>"
        f"<td>{texte(domaine['admin_email'], defaut='non renseigné')}</td>"
        f"<td>{jeton}</td>"
        f'<td class="compact">{horodatage(domaine["verified_at"])}</td>'
        f"<td>{action}</td></tr>"
    )


# --- État du système --------------------------------------------------------


def page_etat(
    composants: Sequence[Mapping[str, Any]], evenements: Sequence[Mapping[str, Any]]
) -> str:
    if composants:
        lignes = "".join(
            f"<tr><td>{texte(ligne['component'])}</td>"
            f"<td>{pastille(ligne['status'], ETATS_COMPOSANT)}</td>"
            f'<td class="compact">{horodatage(ligne["observed_at"])}</td>'
            f"<td>{texte(_raisons(ligne.get('details')), defaut='-')}</td></tr>"
            for ligne in composants
        )
        actuel = (
            "<table><thead><tr><th>Composant</th><th>État</th>"
            "<th>Observé le</th><th>Détail</th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    else:
        actuel = '<p class="vide">Aucun état relevé pour le moment.</p>'

    if evenements:
        lignes = "".join(
            f'<tr><td class="compact">{horodatage(ligne["observed_at"])}</td>'
            f"<td>{texte(ligne['component'])}</td>"
            f"<td>{pastille(ligne.get('previous_status'), ETATS_COMPOSANT)} &rarr; "
            f"{pastille(ligne['status'], ETATS_COMPOSANT)}</td>"
            f"<td>{texte(_raisons(ligne.get('reasons')), defaut='-')}</td></tr>"
            for ligne in evenements
        )
        histoire = (
            "<table><thead><tr><th>Quand</th><th>Composant</th>"
            "<th>Transition</th><th>Motif</th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    else:
        histoire = '<p class="vide">Aucune transition enregistrée.</p>'

    return (
        "<section><h2>État actuel</h2>"
        '<p class="chapeau">Dernier relevé de chaque composant.</p>'
        f"{actuel}</section>"
        "<section><h2>Transitions récentes</h2>"
        '<p class="chapeau">Les changements d\'état, du plus récent au plus '
        "ancien.</p>"
        f"{histoire}</section>"
    )


def _raisons(valeur: Any) -> str:
    """Aplati les motifs, qu'ils viennent d'une liste ou d'un objet JSON."""
    import json

    if isinstance(valeur, str):
        try:
            valeur = json.loads(valeur)
        except ValueError:
            return valeur
    if isinstance(valeur, dict):
        valeur = valeur.get("reasons", valeur)
    if isinstance(valeur, dict):
        return ", ".join(f"{cle}={val}" for cle, val in sorted(valeur.items()))
    if isinstance(valeur, (list, tuple)):
        return ", ".join(str(item) for item in valeur)
    return "" if valeur is None else str(valeur)


# --- Courrier récent --------------------------------------------------------


def page_courrier(
    messages: Sequence[Mapping[str, Any]], limite: int, cite: str = ""
) -> str:
    """Les derniers messages captés, chacun sous la référence qui le nomme."""
    if not messages:
        corps = (
            f'<p class="vide">Aucun message ne porte la référence {escape(cite)}.</p>'
            if cite
            else '<p class="vide">Aucun message capté pour le moment.</p>'
        )
    else:
        lignes = "".join(
            '<tr><td class="compact"><code class="insecable">'
            f'{escape(reference("M", ligne.get("id")))}</code></td>'
            f'<td class="compact">{horodatage(ligne["captured_at"])}</td>'
            f"<td>{pastille(ligne['delivery_status'], ETATS_LIVRAISON)}</td>"
            f"<td>{texte(ligne['from_header'] or ligne['envelope_from'], maximum=70)}"
            "</td>"
            f"<td>{texte(_destinataires(ligne['envelope_recipients']), maximum=70)}"
            "</td>"
            f"<td>{texte(ligne['subject'], defaut='(sans objet)')}</td></tr>"
            for ligne in messages
        )
        corps = (
            "<table>"
            + colonnes("7%", "10%", "7%", "26%", "20%", "30%")
            + "<thead><tr><th>Réf.</th><th>Reçu le</th><th>État</th>"
            "<th>Expéditeur</th><th>Destinataire</th><th>Objet</th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    chapeau = (
        f"Le message cité sous la référence <code>{escape(cite)}</code>. "
        '<a href="/courrier">Revenir au courrier récent</a>'
        if cite
        else f"Les {escape(str(limite))} derniers messages, en lecture seule. Le "
        "contenu des messages et les pièces jointes ne sont pas consultables ici."
    )
    return (
        "<section><h2>Courrier récent</h2>"
        f'<p class="chapeau">{chapeau}</p>'
        f"{corps}</section>"
    )


def _destinataires(valeur: Any) -> str:
    if isinstance(valeur, (list, tuple)):
        return ", ".join(str(item) for item in valeur)
    return "" if valeur is None else str(valeur)


# --- Registre d'apprentissage ----------------------------------------------


def page_apprentissage(
    destinataires: Sequence[Mapping[str, Any]],
    selection: str | None,
    regles: Sequence[Mapping[str, Any]],
    retours: Sequence[Mapping[str, Any]],
    recherche: str = "",
) -> str:
    if destinataires:
        lignes = "".join(
            f'<tr><td><a href="/apprentissage?destinataire={_url(ligne["email"])}">'
            f"{texte(ligne['email'])}</a></td>"
            f'<td class="compact">{texte(ligne["regles"])}</td>'
            f'<td class="compact">{texte(ligne["retours"])}</td></tr>'
            for ligne in destinataires
        )
        liste = (
            "<table><thead><tr><th>Destinataire</th><th>Règles</th>"
            f"<th>Retours</th></tr></thead><tbody>{lignes}</tbody></table>"
        )
    else:
        liste = '<p class="vide">Aucun destinataire n\'a encore de registre.</p>'

    sections = (
        "<section><h2>Destinataires</h2>"
        '<p class="chapeau">Ce que le système a appris, destinataire par '
        "destinataire. Cette page est en lecture seule : les règles se modifient "
        "par échange avec l'assistant.</p>"
        f"{liste}</section>"
    )

    if selection:
        sections += _section_regles(selection, regles, recherche)
        sections += _section_retours(retours)
    return sections


def _badge_action(valeur: Any) -> str:
    action = str(valeur)
    if action == "allow":
        return '<span class="badge badge-vert">laisser passer</span>'
    if action == "hold":
        return '<span class="badge badge-ambre">retenir</span>'
    return f'<span class="badge badge-gris">{escape(action)}</span>'


def _origine(valeur: Any) -> str:
    return {
        "migrated_from_v2": "migration v2",
        "authenticated_smtp_suppression": "réponse B",
        "sent_scan": "correspondant",
    }.get(str(valeur), str(valeur))


def _section_regles(
    selection: str, regles: Sequence[Mapping[str, Any]], recherche: str = ""
) -> str:
    total = int(regles[0]["total"]) if regles else 0
    filtre = (
        f'<form method="get" action="/apprentissage" class="recherche">'
        f'<input type="hidden" name="destinataire" value="{texte(selection)}">'
        f'<input type="search" name="q" value="{texte(recherche, defaut="")}" '
        'placeholder="Filtrer par expéditeur ou domaine…" autocomplete="off">'
        '<button type="submit" class="discret">Filtrer</button></form>'
    )
    compteur = ""
    if total > len(regles):
        compteur = (
            f'<p class="chapeau">{len(regles)} règles affichées sur {total} - '
            "affinez le filtre pour voir le reste.</p>"
        )
    if regles:
        lignes = "".join(
            f"<tr><td class=\"compact\">{texte(_portee(ligne['scope']))}</td>"
            f"<td>{texte(ligne['value_normalized'], maximum=80)}</td>"
            f"<td class=\"compact\">{_badge_action(ligne['action'])}</td>"
            f"<td class=\"compact\">{'active' if ligne['active'] else 'désactivée'}</td>"
            f"<td class=\"compact\">{texte(_origine(ligne['source']), maximum=24)}</td>"
            f'<td class="compact">{horodatage(ligne["updated_at"])}</td></tr>'
            for ligne in regles
        )
        corps = (
            "<table><thead><tr><th>Portée</th><th>Valeur</th><th>Effet</th>"
            "<th>État</th><th>Origine</th><th>Modifiée le</th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    else:
        corps = (
            '<p class="vide">Aucune règle ne correspond à ce filtre.</p>'
            if recherche
            else '<p class="vide">Aucune règle pour ce destinataire.</p>'
        )
    return (
        f"<section><h2>Règles de {texte(selection)}</h2>"
        f"{filtre}{compteur}{corps}</section>"
    )


def _section_retours(retours: Sequence[Mapping[str, Any]]) -> str:
    if retours:
        lignes = "".join(
            f'<tr><td class="compact">{horodatage(ligne["created_at"])}</td>'
            f"<td>{texte(ligne['label'], maximum=40)}</td>"
            f"<td>{texte(ligne['sender_normalized'], maximum=70)}</td>"
            f"<td>{texte(ligne['subject'], defaut='(sans objet)')}</td>"
            f"<td>{'pris en compte' if ligne['active'] else 'écarté'}</td></tr>"
            for ligne in retours
        )
        corps = (
            "<table><thead><tr><th>Quand</th><th>Jugement</th><th>Expéditeur</th>"
            f"<th>Objet</th><th>État</th></tr></thead><tbody>{lignes}</tbody></table>"
        )
    else:
        corps = '<p class="vide">Aucun retour humain enregistré.</p>'
    return f"<section><h2>Retours humains</h2>{corps}</section>"


def _portee(valeur: Any) -> str:
    return {"sender": "expéditeur", "domain": "domaine"}.get(str(valeur), str(valeur))


def _action(valeur: Any) -> str:
    return {"hold": "à retenir", "allow": "à laisser passer"}.get(
        str(valeur), str(valeur)
    )


def _url(valeur: Any) -> str:
    from urllib.parse import quote

    return escape(quote(str(valeur), safe=""))


def page_erreur(titre: str, message: str) -> str:
    corps = (
        f"<section><h2>{escape(titre)}</h2>"
        f'<p class="avis avis-erreur">{escape(message)}</p>'
        '<p><a href="/domaines">Revenir aux domaines</a></p></section>'
    )
    return document(titre, "", corps)


def iterables(rows: Iterable[Any]) -> list[Mapping[str, Any]]:
    """Convertit les enregistrements de la base en dictionnaires."""
    return [dict(row) for row in rows]


# --- Réglages ---------------------------------------------------------------

ETATS_MODELE: Mapping[str, str] = {
    "local": "modèle local",
    "distant": "fournisseur distant",
}


def _cellule_plafond(nom: str, valeur: Any) -> str:
    contenu = "" if valeur is None else escape(str(valeur))
    return (
        f'<td><input type="text" inputmode="numeric" name="{nom}" '
        f'value="{contenu}" placeholder="instance" size="6" '
        'autocomplete="off"></td>'
    )


def _ligne_plafond(domaine: Mapping[str, Any]) -> str:
    identifiant = escape(str(domaine["id"]))
    return (
        f'<tr><form method="post" action="/reglages/plafonds">'
        f'<input type="hidden" name="domaine" value="{identifiant}">'
        f"<td><strong>{texte(domaine['fqdn'])}</strong></td>"
        f"<td>{pastille(str(domaine['status']), ETATS_DOMAINE)}</td>"
        + _cellule_plafond("assistant_horaire", domaine["assistant_hourly_limit"])
        + _cellule_plafond("assistant_quotidien", domaine["assistant_daily_limit"])
        + _cellule_plafond("verdict_horaire", domaine["verdict_hourly_limit"])
        + _cellule_plafond("verdict_quotidien", domaine["verdict_daily_limit"])
        + '<td><button type="submit" class="discret">Enregistrer</button></td>'
        "</form></tr>"
    )


def _ligne_modele(role: str, routage: Mapping[str, Any] | None) -> str:
    libelle = "Échanges avec l'utilisateur" if role == "conversation" else "Verdicts"
    actif = bool(routage and routage["enabled"])
    modele = escape(str(routage["model_name"])) if routage else ""
    etat = "local" if actif else "distant"
    action = (
        '<button type="submit" name="etat" value="distant" class="discret">'
        "Rendre au distant</button>"
        if actif
        else '<button type="submit" name="etat" value="local" class="principal">'
        "Confier au local</button>"
    )
    return (
        f'<tr><form method="post" action="/reglages/modele">'
        f'<input type="hidden" name="role" value="{escape(role)}">'
        f"<td><strong>{escape(libelle)}</strong></td>"
        f"<td>{pastille(etat, ETATS_MODELE)}</td>"
        f'<td><input type="text" name="modele" value="{modele}" '
        'placeholder="qwen2.5:7b" autocomplete="off" required></td>'
        f"<td>{horodatage(routage['updated_at']) if routage else '-'}</td>"
        f"<td>{action}</td></form></tr>"
    )


def page_reglages(
    domaines: Sequence[Mapping[str, Any]],
    routage: Sequence[Mapping[str, Any]],
) -> str:
    if domaines:
        lignes = "".join(_ligne_plafond(domaine) for domaine in domaines)
        plafonds = (
            "<table><thead><tr><th>Domaine</th><th>État</th>"
            "<th>Échanges / h</th><th>Échanges / j</th>"
            "<th>Verdicts / h</th><th>Verdicts / j</th><th></th></tr></thead>"
            f"<tbody>{lignes}</tbody></table>"
        )
    else:
        plafonds = '<p class="vide">Aucun domaine enregistré.</p>'

    connu = {str(ligne["role"]): ligne for ligne in routage}
    modeles = "".join(
        _ligne_modele(role, connu.get(role)) for role in ("conversation", "verdict")
    )
    return (
        "<section><h2>Plafonds par domaine</h2>"
        '<p class="chapeau">Un champ vide suit le plafond de l\'instance : c\'est '
        "l'absence de valeur qui fait hériter, jamais un zéro. Ces plafonds "
        "empêchent un domaine de consommer la part des autres ; le plafond "
        "global de l'instance reste au-dessus.</p>"
        f"{plafonds}</section>"
        "<section><h2>Modèle par rôle</h2>"
        '<p class="chapeau">Les échanges n\'engagent aucune livraison et peuvent '
        "passer en local bien avant les verdicts. Un échec local repart chez le "
        "fournisseur distant. Éprouve un modèle avant de lui confier un rôle : "
        "<code>python -m sentimail_v3.supervision.local_llm --probe &lt;modèle&gt;</code>.</p>"
        "<table><thead><tr><th>Rôle</th><th>Sert</th><th>Modèle local</th>"
        "<th>Modifié le</th><th></th></tr></thead>"
        f"<tbody>{modeles}</tbody></table></section>"
    )


# --- Mesure d'efficacité ----------------------------------------------------

_ISSUES: tuple[tuple[str, str], ...] = (
    ("deliver", "Livré sans rien demander"),
    ("ask_user", "Avis demandé"),
    ("filed_as_junk", "Classé indésirable"),
)


def _pourcentage(valeur: Any, *, defaut: str = "-") -> str:
    if not isinstance(valeur, (int, float)) or isinstance(valeur, bool):
        return defaut
    return f"{valeur * 100:.1f} %"


def _entier(valeur: Any) -> str:
    return str(valeur) if isinstance(valeur, int) and not isinstance(valeur, bool) else "-"


def page_mesure(rapport: Any, observe_le: Any) -> str:
    """Ce que la chaîne décide, et ce qu'elle se trompe de décider.

    L'ordre de la page n'est pas cosmétique. La couverture vient avant les
    taux, parce qu'un taux calculé sur une poignée de messages se lit comme un
    taux calculé sur des milliers si rien ne dit le contraire. La colonne
    « non qualifié » reste affichée : la masquer ferait croire que la ligne
    « livré » est mesurée alors qu'elle ne l'est presque pas.
    """
    if not isinstance(rapport, Mapping) or not isinstance(
        rapport.get("matrix"), Mapping
    ):
        return (
            "<h2>Mesure d’efficacité</h2>"
            '<p class="vide">Aucune mesure publiée pour le moment. '
            "Le rapport est produit par le service d’entretien à chaque cycle.</p>"
        )

    matrice = rapport["matrix"].get("rows", {})
    couverture = rapport.get("coverage", {})

    lignes_couverture = "".join(
        f"<tr><td>{texte(libelle)}</td>"
        f"<td>{_entier((couverture.get(cle) or {}).get('total'))}</td>"
        f"<td>{_entier((couverture.get(cle) or {}).get('labelled'))}</td>"
        f"<td>{_pourcentage((couverture.get(cle) or {}).get('rate'))}</td></tr>"
        for cle, libelle in _ISSUES
    )

    lignes_matrice = "".join(
        f"<tr><td>{texte(libelle)}</td>"
        f"<td>{_entier((matrice.get(cle) or {}).get('legitimate'))}</td>"
        f"<td>{_entier((matrice.get(cle) or {}).get('spam'))}</td>"
        f"<td>{_entier((matrice.get(cle) or {}).get('ambiguous'))}</td>"
        f"<td>{_entier((matrice.get(cle) or {}).get('unknown'))}</td>"
        f"<td>{_entier((matrice.get(cle) or {}).get('total'))}</td></tr>"
        for cle, libelle in _ISSUES
    )

    retenue = rapport.get("hold_precision") or {}
    risque = rapport.get("generalized_risk") or {}
    taux = rapport.get("trec_rates") or {}
    utilite = rapport.get("utility") or {}

    borne = (
        " Aucun sondage aléatoire des messages livrés n’existe : ce nombre est "
        "une <strong>borne inférieure</strong>, pas une mesure. La valeur réelle "
        "est inconnue."
        if risque.get("lower_bound_only")
        else ""
    )

    return (
        "<h2>Mesure d’efficacité</h2>"
        f'<p class="compact">Fenêtre : {texte(rapport.get("window_days"))} jours · '
        f"publié le {horodatage(observe_le)} · "
        f'{_entier(rapport["matrix"].get("total"))} messages.</p>'

        "<h3>Couverture de qualification</h3>"
        "<p>Sur quelle part de chaque issue une conclusion est permise. "
        "À lire avant tout le reste.</p>"
        "<table><thead><tr><th>Issue</th><th>Messages</th>"
        "<th>Qualifiés</th><th>Couverture</th></tr></thead>"
        f"<tbody>{lignes_couverture}</tbody></table>"

        "<h3>Matrice</h3>"
        "<p>Effectifs bruts. La colonne « non qualifié » n’est jamais répartie : "
        "ce qui n’a pas été jugé par un humain ne compte dans aucun taux.</p>"
        "<table><thead><tr><th>Décision du système</th><th>Légitime</th>"
        "<th>Indésirable</th><th>Ambigu</th><th>Non qualifié</th>"
        "<th>Total</th></tr></thead>"
        f"<tbody>{lignes_matrice}</tbody></table>"

        "<h3>Précision de la retenue</h3>"
        f"<p>Quand le système a demandé un avis, il avait raison "
        f'<strong>{_pourcentage(retenue.get("value"))}</strong> du temps '
        f'({_entier(retenue.get("labelled"))} réponses sur '
        f'{_entier(retenue.get("total"))} demandes). '
        "C’est la seule métrique dont la vérité terrain est presque complète.</p>"

        "<h3>Risque d’échec silencieux</h3>"
        f'<p><strong>{_pourcentage(risque.get("value"))}</strong> des messages ont '
        "été livrés alors qu’ils étaient indésirables "
        f'({_entier(risque.get("observed"))} observés).{borne}</p>'

        "<h3>Taux d’erreur, entre deux bornes</h3>"
        "<p>Une retenue n’est ni une réussite ni un échec : c’est un report. "
        "Chaque taux est donc donné en la comptant d’abord comme juste, puis "
        "comme erreur. L’écart mesure ce que le système délègue au lieu de "
        "trancher.</p>"
        "<table><thead><tr><th>Erreur</th><th>Retenue comptée juste</th>"
        "<th>Retenue comptée fausse</th></tr></thead><tbody>"
        f'<tr><td>Légitime non livré</td><td>{_pourcentage(taux.get("hm_optimistic"))}</td>'
        f'<td>{_pourcentage(taux.get("hm_pessimistic"))}</td></tr>'
        f'<tr><td>Indésirable livré</td><td>{_pourcentage(taux.get("sm_optimistic"))}</td>'
        f'<td>{_pourcentage(taux.get("sm_pessimistic"))}</td></tr>'
        "</tbody></table>"

        "<h3>Score d’utilité</h3>"
        f'<p><strong>{texte(round(utilite["normalised"], 3)) if isinstance(utilite.get("normalised"), float) else "-"}</strong> '
        "sur une échelle de -1 à +1, calculé sur "
        f'{_entier(utilite.get("scored"))} messages qualifiés. '
        "Les poids sont ceux publiés par SE Labs pour noter les passerelles de "
        "messagerie : ils ne viennent pas de nous, et restent une opinion "
        "défendable plutôt qu’une vérité.</p>"
    )


# --- Moteur de langage ------------------------------------------------------

# Chaque rôle choisit librement son moteur : rien n'impose au verdict et à la
# conversation de partager le même fournisseur. Un préréglage ne fait que
# préremplir l'adresse et le modèle - l'opérateur peut encore les ajuster
# avant d'enregistrer, et ``custom`` reste ouvert pour un fournisseur maison.
_LIBELLES_ROLE: Mapping[str, str] = {
    "verdict": "Verdict",
    "conversation": "Conversation",
}

_PRESETS_LIBELLES: tuple[tuple[str, str], ...] = (
    ("deepseek", "DeepSeek"),
    ("openai", "ChatGPT (OpenAI)"),
    ("mistral", "Mistral"),
    ("anthropic", "Claude (Anthropic)"),
    ("ollama", "Ollama (local)"),
    ("custom", "Personnalisé"),
)


def preset_effectif(
    role: str,
    ligne: Mapping[str, Any] | None,
    preset_choisi: Mapping[str, str] | None,
) -> str:
    """Le préréglage qui gouverne ce rôle en ce moment.

    D'abord le choix explicite (un clic sur un lien de préréglage) ; sinon ce
    que la configuration déjà enregistrée laisse deviner - son adresse
    correspond-elle exactement à celle d'un préréglage connu ? - sinon
    ``custom``, qui est toujours un refus honnête plutôt qu'une devinette.
    """
    force = (preset_choisi or {}).get(role)
    if force in PRESETS:
        return force
    if ligne:
        base_url = str(ligne.get("base_url") or "")
        for nom, preset in PRESETS.items():
            if nom != "custom" and preset.base_url == base_url:
                return nom
    return "custom"


def _carte_moteur(
    role: str,
    ligne: Mapping[str, Any] | None,
    preset_choisi: Mapping[str, str] | None,
) -> str:
    preregle = preset_effectif(role, ligne, preset_choisi)
    if (preset_choisi or {}).get(role) in PRESETS:
        # Un préréglage vient d'être choisi : ses valeurs prérempliront le
        # formulaire, même si un autre moteur était déjà en place.
        valeurs = PRESETS[preregle]
        base_url = valeurs.base_url
        modele = valeurs.model
    else:
        base_url = str(ligne.get("base_url") or "") if ligne else ""
        modele = str(ligne.get("model_name") or "") if ligne else ""

    pose = bool(ligne) and bool(ligne.get("secret_pose"))
    placeholder_cle = "inchangée si vide" if pose else "clé de l'API"

    liens = " · ".join(
        f'<a href="/reglages?role={escape(role)}&preset={cle}">{escape(libelle)}</a>'
        for cle, libelle in _PRESETS_LIBELLES
    )

    # `ligne` peut être un repère synthétique (juste {"role", "secret_pose"})
    # posé par /reglages quand aucune configuration n'existe encore pour ce
    # rôle : sur ce repère, `base_url` est absent, alors qu'une vraie ligne
    # de `llm_role_providers` en porte toujours un (colonne NOT NULL). C'est
    # ce qui distingue « configuré » de « rien à afficher ».
    if ligne and ligne.get("base_url"):
        etat = (
            f'<p class="compact">Configuré par {texte(ligne.get("configured_by"))} '
            f"le {horodatage(ligne.get('validated_at'))}.</p>"
        )
    else:
        etat = '<p class="vide">Aucun moteur configuré pour ce rôle.</p>'

    libelle_role = _LIBELLES_ROLE.get(role, role)
    return (
        f"<section><h3>{escape(libelle_role)}</h3>"
        f'<p class="chapeau">Préréglages : {liens}</p>'
        f"{etat}"
        f'<form method="post" action="/reglages/moteur" autocomplete="off">'
        f'<input type="hidden" name="role" value="{escape(role)}">'
        f'<input type="hidden" name="preset" value="{escape(preregle)}">'
        '<div class="champs">'
        f'<div><label for="base_url_{escape(role)}">Adresse (base_url)</label>'
        f'<input type="text" id="base_url_{escape(role)}" name="base_url" '
        f'value="{escape(base_url)}" autocomplete="off" required></div>'
        f'<div><label for="modele_{escape(role)}">Modèle</label>'
        f'<input type="text" id="modele_{escape(role)}" name="modele" '
        f'value="{escape(modele)}" autocomplete="off" required></div>'
        f'<div><label for="cle_{escape(role)}">Clé API</label>'
        f'<input type="password" id="cle_{escape(role)}" name="cle" '
        f'placeholder="{escape(placeholder_cle)}" autocomplete="new-password" '
        "spellcheck=\"false\"></div>"
        "</div>"
        '<button type="submit" class="principal">Enregistrer</button>'
        "</form></section>"
    )


def page_reglages_moteur(
    rows: Sequence[Mapping[str, Any]] | None,
    routage: Sequence[Mapping[str, Any]] | None = None,
    preset_choisi: Mapping[str, str] | None = None,
) -> str:
    """Le moteur de langage, une carte par rôle.

    Le champ « clé » ne se réaffiche jamais : la console n'a aucun moyen de
    relire ce qu'elle a posé, et il ne faut pas laisser croire le contraire.
    ``routage`` n'est pas utilisé ici - il sert l'encart de confidentialité,
    affiché juste après cette section - mais reste accepté pour que les deux
    fonctions partagent le même appel depuis ``/reglages``.
    """
    connu = {str(ligne["role"]): ligne for ligne in (rows or [])}
    cartes = "".join(
        _carte_moteur(role, connu.get(role), preset_choisi)
        for role in ("verdict", "conversation")
    )
    return f"<h2>Moteur de langage</h2>{cartes}"


def encart_confidentialite(
    rows: Sequence[Mapping[str, Any]] | None,
    routage: Sequence[Mapping[str, Any]] | None = None,
) -> str:
    """Où part le contenu du courrier, rôle par rôle - rien de plus.

    C'est le seul renseignement qui compte pour la confidentialité : soit le
    courrier sort vers une adresse distante, soit un modèle local le retient.
    Aucune autre valeur technique n'est montrée ici.
    """
    connu_moteur = {str(ligne["role"]): ligne for ligne in (rows or [])}
    connu_local = {str(ligne["role"]): ligne for ligne in (routage or [])}
    lignes = "".join(
        _ligne_confidentialite(role, connu_moteur.get(role), connu_local.get(role))
        for role in ("verdict", "conversation")
    )
    return (
        "<section><h2>Confidentialité</h2>"
        '<p class="chapeau">Où part le contenu du courrier, rôle par rôle.</p>'
        f"{lignes}</section>"
    )


def _ligne_confidentialite(
    role: str,
    moteur: Mapping[str, Any] | None,
    local: Mapping[str, Any] | None,
) -> str:
    libelle = _LIBELLES_ROLE.get(role, role)
    if local and local.get("enabled"):
        phrase = (
            f"<strong>{escape(libelle)}</strong> : rôle servi par le modèle "
            f"local {texte(local.get('model_name'))} - rien ne sort."
        )
        if local.get("fallback_enabled"):
            phrase += (
                " En cas d'échec local, le courrier repart vers le "
                "fournisseur distant configuré ci-dessus."
            )
        return f"<p>{phrase}</p>"
    # Même repère synthétique qu'en haut de cette page : sans `base_url`,
    # il n'y a rien de réel à annoncer comme destination du courrier.
    if moteur and moteur.get("base_url"):
        return (
            f"<p><strong>{escape(libelle)}</strong> : le contenu du courrier "
            f"part vers {texte(moteur.get('base_url'))} "
            f"(modèle {texte(moteur.get('model_name'))}).</p>"
        )
    return f"<p><strong>{escape(libelle)}</strong> : aucun moteur configuré.</p>"


# --- Identité de l'instance ---------------------------------------------------

_CHAMPS_IDENTITE: tuple[tuple[str, str, str], ...] = (
    ("action_address", "Adresse d'action", "maia@sentinel.exemple.org"),
    ("action_aliases", "Alias (séparés par des virgules)", "kitt@sentinel.exemple.org"),
    ("assistant_sender", "Expéditeur des avis (MAIA)", "MAIA — SentiMail <maia@exemple.org>"),
    ("probe_recipient", "Destinataire de la sonde", "sentinel-probe@exemple.org"),
)


def page_reglages_identite(
    row: Mapping[str, Any] | None,
    valeurs_env: Mapping[str, Any] | None = None,
) -> str:
    """L'identité de l'instance : où le courrier d'action arrive, qui il dit être.

    Tant qu'aucune ligne n'existe dans ``instance_identity``, l'instance tourne
    sur les variables d'environnement du service - montrées ici telles
    quelles, avec un bouton qui les copie en base pour que l'exploitant en
    devienne maître sans avoir à les retaper. Une fois la ligne posée, elle
    prime sur l'environnement, et le formulaire l'édite directement.
    """
    env = valeurs_env or {}
    if row:
        valeurs = {
            "action_address": str(row.get("action_address") or ""),
            "action_aliases": ", ".join(row.get("action_aliases") or []),
            "assistant_sender": str(row.get("assistant_sender") or ""),
            "probe_recipient": str(row.get("probe_recipient") or ""),
        }
        etat = (
            f'<p class="compact">Configurée par {texte(row.get("configured_by"))} '
            f"le {horodatage(row.get('updated_at'))}.</p>"
        )
        libelle_bouton = "Enregistrer"
    else:
        valeurs = {
            "action_address": str(env.get("action_address") or ""),
            "action_aliases": ", ".join(env.get("action_aliases") or []),
            "assistant_sender": str(env.get("assistant_sender") or ""),
            "probe_recipient": str(env.get("probe_recipient") or ""),
        }
        etat = (
            "<p class=\"vide\">Aucune identité enregistrée : l'instance suit "
            "les valeurs de l'environnement, affichées ci-dessous.</p>"
        )
        libelle_bouton = "Reprendre la main"

    champs = "".join(
        f'<div><label for="{nom}">{escape(libelle)}</label>'
        f'<input type="text" id="{nom}" name="{nom}" '
        f'value="{escape(valeurs[nom])}" placeholder="{escape(exemple)}" '
        f'autocomplete="off"{" required" if nom != "action_aliases" else ""}></div>'
        for nom, libelle, exemple in _CHAMPS_IDENTITE
    )

    return (
        "<section><h2>Identité de l'instance</h2>"
        '<p class="chapeau">L\'adresse d\'action, ses alias, l\'expéditeur des '
        "avis MAIA et le destinataire de la sonde de bout en bout.</p>"
        f"{etat}"
        '<form method="post" action="/reglages/identite" autocomplete="off">'
        f'<div class="champs">{champs}</div>'
        f'<button type="submit" class="principal">{escape(libelle_bouton)}</button>'
        "</form></section>"
    )


# --- Écarts humain/modèle ----------------------------------------------------

# Les quatre sens d'un écart, dans les mots de la lettre d'entretien. Les deux
# premiers sont de vraies erreurs ; les deux autres, de la prudence voulue.
SENS_ECARTS: tuple[tuple[str, str, str], ...] = (
    ("laisse_passer", "Livré, jugé indésirable", "ambre"),
    ("erreur_de_qualification", "Écarté, jugé ordinaire", "ambre"),
    ("demande_au_lieu_de_classer", "Avis demandé, jugé indésirable", "vert"),
    ("demande_au_lieu_de_livrer", "Avis demandé, jugé ordinaire", "vert"),
)


def _contexte_label(brut: object) -> Mapping[str, Any]:
    """Le contexte du label, lu sans confiance : absent ou illisible = vide."""
    if isinstance(brut, Mapping):
        return brut
    if isinstance(brut, str) and brut:
        try:
            value = json.loads(brut)
        except ValueError:
            return {}
        if isinstance(value, Mapping):
            return value
    return {}


# Le préambule qu'un jugement rejeté porte devant sa motivation d'origine.
# La console dit déjà, en plus précis, ce qui a empêché de conclure : répété
# ici, il occupait les deux phrases qu'on avait pour dire le fond.
_PREAMBULE = "Ce que j’avais retenu jusque-là :"


def _sans_preambule(raisonnement: object) -> str:
    """La motivation seule, débarrassée de l'annonce qui la précède."""
    brut = str(raisonnement or "")
    tete, marqueur, reste = brut.partition(_PREAMBULE)
    return reste.strip() if marqueur else brut


def _conclusion(raisonnement: object, phrases: int = 2) -> str:
    """Le début du raisonnement, coupé sur une fin de phrase.

    Un raisonnement de verdict fait dix lignes ; instruire un écart n'en
    demande pas dix, il demande de quoi reconnaître le cas. Couper au nombre
    de caractères tranchait au milieu d'un mot : on coupe donc après un point,
    et on se rabat sur la troncature ordinaire quand aucun point ne vient.
    """
    brut = str(raisonnement or "").replace("\r", " ").replace("\n", " ").strip()
    if not brut:
        return ""
    garde = 0
    for _ in range(phrases):
        # Le point d'une abréviation ou d'un domaine ne finit pas une phrase :
        # une vraie fin est suivie d'une espace et d'une majuscule, ou de rien.
        suivant = _FIN_DE_PHRASE.search(brut, garde)
        if suivant is None:
            garde = 0
            break
        garde = suivant.end()
    return brut[:garde].strip() if garde else brut


# Une fin de phrase : ponctuation forte, puis la fin du texte ou une espace
# suivie d'une majuscule. « chatgpt.com » ou « M. Dupont » n'en sont pas.
_FIN_DE_PHRASE = re.compile(r"[.!?](?=\s+[A-ZÀ-Þ«]|\s*$)")


# Ce qu'un blocage veut dire, dit en français. Le moteur écrit ces motifs pour
# lui-même : ils nomment le fait du dossier qui a interdit la livraison, et
# c'est très exactement ce qu'on cherche en instruisant un écart. Non traduits,
# ils obligeaient à lire le code pour comprendre une ligne de console.
BLOCAGES: Mapping[str, str] = {
    "deep_execution_incomplete": "l'analyse profonde n'a pas abouti",
    "static_investigation_incomplete": "les vérifications de base n'ont pas abouti",
    "material_danger_unresolved": "une preuve matérielle de danger restait sans réponse",
    "authenticated_hold_ignored": "une consigne de retenue portait sur cet expéditeur",
    "confidence_below_judicial_threshold": "la confiance restait sous le seuil exigé",
    "delivery_requires_legitimate": "le moteur ne concluait pas à un message légitime",
    "delivery_forbids_verdict_doubt": "le moteur gardait un doute",
    "legitimate_must_be_delivered": "un message jugé légitime ne peut pas être retenu",
    "junk_requires_spam_or_dangerous": "classer exige de conclure spam ou dangereux",
}


def _blocage(brut: object) -> list[str]:
    """Les motifs qui ont interdit la livraison, traduits quand ils le sont."""
    if isinstance(brut, str) and brut:
        try:
            valeur = json.loads(brut)
        except ValueError:
            return []
    else:
        valeur = brut
    if not isinstance(valeur, list):
        return []
    return [BLOCAGES.get(str(item), str(item)) for item in valeur][:3]


def _charges(brut: object) -> list[Mapping[str, Any]]:
    """Les indices à charge de l'enquête, du plus fort au plus faible."""
    if isinstance(brut, str) and brut:
        try:
            valeur = json.loads(brut)
        except ValueError:
            return []
    else:
        valeur = brut
    if not isinstance(valeur, list):
        return []
    return [item for item in valeur if isinstance(item, Mapping)]


def _elements_ecart(ecart: Mapping[str, Any]) -> str:
    """Ce qu'il faut savoir pour instruire l'écart, et rien de plus.

    Un écart s'instruit en répondant à une question : qu'est-ce que le moteur
    avait à opposer que l'humain a écarté ? Le volet donnait auparavant tout
    le dossier - le raisonnement entier, les vingt-quatre critères observés,
    favorables compris, et la liste brute que le modèle avait recopiée - si
    bien que l'unique indice qui avait fait basculer le verdict s'y perdait.

    Quatre lignes suffisent : les deux jugements, ce qui pesait contre, ce que
    le moteur n'a pas pu vérifier, et les mots de la personne. Le reste du
    dossier se consulte ailleurs ; ici, il empêchait de voir.
    """
    contexte = _contexte_label(ecart.get("label_context"))
    confiance = (
        f" ({float(ecart['model_confidence']):.2f})"
        if ecart.get("model_confidence") is not None
        else ""
    )
    blocs: list[str] = [
        "<p><strong>Moteur</strong> "
        + texte(ecart.get("model_classification")) + confiance
        + " · <strong>Humain</strong> " + texte(ecart.get("human_label")) + "</p>"
    ]

    # Ce qui pesait contre : les charges de l'enquête, dites en clair. Sans
    # elles, un désaccord se lit comme un caprice de part et d'autre.
    charges = _charges(ecart.get("charges"))
    if charges:
        puces = "".join(
            "<li>" + texte(charge.get("statement"), maximum=200)
            + f' <code>{escape(str(charge.get("code") or ""))}</code>'
            + f' <span class="compact">{escape(str(charge.get("strength") or ""))}</span>'
            + "</li>"
            for charge in charges[:3]
        )
        blocs.append(f"<p><strong>Ce qui pesait contre</strong></p><ul>{puces}</ul>")
    elif ecart.get("message_id"):
        blocs.append(
            "<p><strong>Ce qui pesait contre :</strong> rien à charge dans "
            "l'enquête.</p>"
        )
    else:
        # Message purgé : il ne reste que les critères que l'avis portait.
        signals = contexte.get("signals")
        if isinstance(signals, list) and signals:
            codes = " ".join(
                f"<code>{escape(str(code))}</code>" for code in signals[:12]
            )
            blocs.append(
                "<p>Message purgé ; critères retenus à l'époque : " + codes + "</p>"
            )

    # Le fait qui a interdit la livraison. Il n'est pas une charge - il n'accuse
    # personne - mais il explique à lui seul qu'un message sain se soit vu
    # poser une question, et c'est souvent lui, et non les indices, qu'il faut
    # corriger.
    blocage = _blocage(ecart.get("blocage"))
    if blocage:
        blocs.append(
            "<p><strong>Ce qui a interdit la livraison :</strong> "
            + escape(", ".join(blocage)) + ".</p>"
        )
    elif ecart.get("deep_complete") is False:
        blocs.append(
            "<p><strong>Analyse profonde :</strong> inachevée.</p>"
        )

    conclusion = _conclusion(_sans_preambule(ecart.get("model_rationale")))
    if conclusion:
        blocs.append(
            "<p><strong>Sa conclusion :</strong> "
            + texte(conclusion, maximum=400) + "</p>"
        )

    user_reason = contexte.get("user_reason")
    if user_reason:
        blocs.append(
            '<p class="compact">Ta réponse : « '
            + texte(user_reason, maximum=200) + " »</p>"
        )
    return "".join(blocs)


def page_ecarts(
    metriques: Sequence[Mapping[str, Any]],
    ecarts: Sequence[Mapping[str, Any]],
    vue_traites: bool,
    cite: str = "",
) -> str:
    """Les désaccords humain/modèle, instruits comme des vulnérabilités.

    En tête, la mesure : tous les écarts, traités compris - l'acquittement ne
    réécrit jamais la mesure. En dessous, la liste à instruire : chaque ligne
    est un cas précis, marqué traité quand un exploitant l'a analysé.
    """
    par_sens = {str(ligne["direction"]): ligne for ligne in metriques}
    lignes_mesure = "".join(
        "<tr><td>"
        + f'<span class="badge badge-{teinte}">{escape(libelle)}</span>'
        + "</td>"
        + '<td class="compact">' + texte(ligne.get("j7"), defaut="0") + "</td>"
        + '<td class="compact">' + texte(ligne.get("j30"), defaut="0") + "</td>"
        + '<td class="compact">' + texte(ligne.get("ouverts"), defaut="0") + "</td></tr>"
        for sens, libelle, teinte in SENS_ECARTS
        for ligne in [par_sens.get(sens, {})]
    )
    mesure = (
        "<table>"
        + colonnes("46%", "18%", "18%", "18%")
        + "<thead><tr><th>Sens</th><th>7 jours</th><th>30 jours</th>"
        "<th>À traiter</th></tr></thead>"
        "<tbody>" + lignes_mesure + "</tbody></table>"
    )
    libelles = {sens: (libelle, teinte) for sens, libelle, teinte in SENS_ECARTS}
    if ecarts:
        lignes = "".join(
            '<tr><td class="compact"><code class="insecable">'
            + escape(reference("E", ecart.get("id"))) + "</code></td>"
            + '<td class="compact">' + texte(str(ecart["created_at"])[:16]) + "</td>"
            + "<td>" + texte(ecart.get("participant_email"), maximum=40) + "</td>"
            + "<td>" + texte(ecart.get("sender_normalized"), maximum=40) + "</td>"
            + "<td>" + texte(ecart.get("subject"), maximum=60) + "</td>"
            + "<td>" + texte(ecart.get("model_classification"))
            + (
                f' <span class="compact">({float(ecart["model_confidence"]):.2f})</span>'
                if ecart.get("model_confidence") is not None
                else ""
            )
            + " → " + texte(ecart.get("human_label")) + "</td>"
            + "<td>"
            + '<span class="badge badge-{1}">{0}</span>'.format(
                *libelles.get(str(ecart["direction"]), (str(ecart["direction"]), "gris"))
            )
            + "</td><td>"
            + (
                '<span class="compact">traité le '
                + texte(str(ecart.get("acknowledged_at"))[:16])
                + " par " + texte(ecart.get("acknowledged_by"), maximum=24)
                + "</span>"
                if ecart.get("acknowledged_at")
                else '<form method="post" action="/ecarts/traiter" class="enligne">'
                + '<input type="hidden" name="id" value="' + texte(ecart["id"]) + '">'
                + '<button type="submit">Marquer traité</button></form>'
            )
            + "</td></tr>"
            # Chaque écart porte, sous sa ligne, les éléments des deux
            # jugements : sans eux, on ne peut ni rappeler le cas ni le
            # corriger. Un volet natif, aucun script.
            + '<tr><td colspan="8" class="elements"><details>'
            + "<summary>Éléments du jugement</summary>"
            + _elements_ecart(ecart)
            + "</details></td></tr>"
            for ecart in ecarts
        )
        tableau = (
            "<table>"
            + colonnes("8%", "12%", "12%", "13%", "16%", "14%", "13%", "12%")
            + "<thead><tr><th>Réf.</th><th>Jugé le</th><th>Destinataire</th>"
            "<th>Expéditeur</th><th>Objet</th><th>Modèle → humain</th>"
            "<th>Sens</th><th></th></tr></thead>"
            "<tbody>" + lignes + "</tbody></table>"
        )
    elif cite:
        tableau = (
            f'<p class="vide">Aucun écart ne porte la référence {escape(cite)}.</p>'
        )
    elif vue_traites:
        tableau = '<p class="vide">Aucun écart traité pour le moment.</p>'
    else:
        tableau = (
            '<p class="vide">Aucun écart à traiter : les jugements humains '
            "et les verdicts concordent, ou tout a été instruit.</p>"
        )
    if cite:
        # Une référence désigne un dossier, pas une file : le partage entre
        # ouverts et traités n'a plus de sens une fois qu'on cite.
        bascule = (
            '<p class="chapeau">L\'écart cité sous la référence '
            f"<code>{escape(cite)}</code>. "
            '<a href="/ecarts">Revenir aux écarts à traiter</a></p>'
        )
        titre_liste = f"Écart {escape(cite)}"
    else:
        bascule = (
            '<p class="chapeau"><a href="/ecarts">← Revenir aux écarts à traiter</a></p>'
            if vue_traites
            else '<p class="chapeau"><a href="/ecarts?vue=traites">Voir les écarts déjà traités</a></p>'
        )
        titre_liste = "Écarts traités" if vue_traites else "Écarts à traiter"
    return (
        "<section><h2>La mesure des désaccords</h2>"
        '<p class="chapeau">Chaque écart compare un jugement humain au verdict '
        "rendu sur le même message. Les deux premiers sens sont de vraies "
        "erreurs du moteur ; les deux autres sont la prudence voulue - il n'a "
        "pas tranché, il a demandé. Marquer un écart traité le sort de la "
        "liste et du courrier d'entretien, jamais de cette mesure.</p>"
        + mesure + "</section>"
        + f"<section><h2>{titre_liste}</h2>"
        + bascule + tableau + "</section>"
    )


# --- Sources hostiles --------------------------------------------------------


# Comment une adresse est entrée au registre, dit en français. Le motif est
# écrit par le moteur sous la forme « origine_qualification » : lisible pour
# lui, opaque sur une page. « backfill_spam » n'apprenait rien à personne.
ORIGINES_SOURCE: Mapping[str, str] = {
    "verdict": "verdict du moteur",
    "user_feedback": "ta qualification",
    "backfill": "reprise d'historique",
    "manual": "ajout manuel",
}

QUALIFICATIONS_SOURCE: Mapping[str, str] = {
    "spam": "indésirable",
    "dangerous": "dangereux",
    "malicious": "malveillant",
    "suspect": "suspect",
    "admin": "console",
}


def motif_source(brut: object) -> str:
    """Le motif d'une source, traduit ; à défaut, rendu tel quel.

    On ne traduit que ce qu'on connaît : un motif introduit plus tard doit
    rester lisible en clair plutôt que de disparaître derrière un « autre ».
    """
    valeur = str(brut or "").strip()
    if not valeur:
        return "-"
    # Une origine peut elle-même contenir un souligné (« user_feedback ») :
    # couper au premier séparateur donnait « user » et perdait le motif.
    for origine in sorted(ORIGINES_SOURCE, key=len, reverse=True):
        if valeur == origine or valeur.startswith(origine + "_"):
            lisible = ORIGINES_SOURCE[origine]
            qualifie = QUALIFICATIONS_SOURCE.get(valeur[len(origine) + 1:])
            # Une entrée manuelle n'a pas de qualification à porter : c'est
            # quelqu'un qui l'a mise là, et c'est tout ce qu'il y a à dire.
            if origine == "manual" or not qualifie:
                return lisible.capitalize()
            return f"{qualifie.capitalize()} - {lisible}"
    return valeur


ETATS_SOURCE: Mapping[str, tuple[str, str]] = {
    "bloquee": ("ambre", "refusée par le MX"),
    "surveillee": ("vert", "surveillée"),
}


def page_sources(
    sources: Sequence[Mapping[str, Any]], export_actifs: int, recherche: str = ""
) -> str:
    """Le registre des serveurs SMTP hostiles, et le geste d'en ajouter.

    Les entrées automatiques viennent des verdicts et des qualifications ;
    elles expirent à 30 jours glissants. Les entrées manuelles restent jusqu'à
    leur suppression. Le fichier lu par le MX suit le registre à la minute. Le
    rDNS affiché est celui que le MX avait résolu à la réception : aucune
    requête n'est refaite.

    L'adresse est la clé de lecture de cette page. Elle passe donc en tête,
    d'un seul tenant - coupée en trois lignes, « 93.184.216.99/32 » n'est plus
    une adresse - et le rDNS se range sous elle, là où il ne laisse pas une
    colonne vide neuf fois sur dix. Le motif, lui, se dit en français : le
    code interne du moteur n'apprenait rien à qui lit la page.
    """
    filtre = (
        '<form method="get" action="/sources" class="recherche">'
        '<input type="search" name="q" value="' + texte(recherche, defaut="")
        + '" placeholder="Filtrer par adresse, rDNS ou motif…" autocomplete="off">'
        '<button type="submit">Filtrer</button></form>'
    )
    if sources:
        lignes = "".join(
            '<tr><td><code class="insecable">' + texte(source["ip"]) + "</code>"
            + (
                '<div class="secondaire">' + texte(source.get("rdns"), maximum=48)
                + "</div>"
                if source.get("rdns")
                else ""
            )
            + "</td>"
            + "<td>" + escape(motif_source(source.get("last_reason"))) + "</td>"
            + '<td class="compact">' + texte(source["hits"]) + "</td>"
            + '<td class="compact">' + texte(str(source["last_seen"])[:16]) + "</td>"
            + "<td>"
            + '<span class="badge badge-{0}">{1}</span>'.format(
                *ETATS_SOURCE.get(str(source.get("etat")), ("gris", "expirée"))
            )
            + "</td>"
            + '<td><form method="post" action="/sources/supprimer" class="enligne">'
            + '<input type="hidden" name="ip" value="' + texte(source["ip"]) + '">'
            + '<button type="submit">Retirer</button></form></td></tr>'
            for source in sources
        )
        tableau = (
            "<table>"
            + colonnes("30%", "22%", "9%", "14%", "15%", "10%")
            + "<thead><tr><th>Adresse / plage</th><th>Motif</th>"
            "<th>Messages</th><th>Vu le</th><th>État</th><th></th></tr></thead>"
            "<tbody>" + lignes + "</tbody></table>"
        )
    elif recherche:
        tableau = '<p class="vide">Aucune source ne correspond à ce filtre.</p>'
    else:
        tableau = '<p class="vide">Aucune source au registre pour le moment.</p>'
    return (
        "<section><h2>Serveurs SMTP hostiles</h2>"
        '<p class="chapeau">Chaque indésirable confirmé laisse ici l\'adresse '
        f"de son serveur. Le MX en refuse {export_actifs} en ce moment : il "
        "faut 10 messages hostiles pour en arriver là (554 explicite, "
        "journalisé), en dessous la source est seulement surveillée. Une "
        "entrée automatique expire après 30 jours sans récidive ; une entrée "
        "manuelle bloque jusqu\'à son retrait.</p>"
        + filtre + tableau + "</section>"
        "<section><h2>Ajouter une adresse ou une plage</h2>"
        '<p class="chapeau">Publique uniquement - une plage interne serait '
        "refusée. Au plus /16.</p>"
        '<form method="post" action="/sources/ajouter">'
        '<div class="champs">'
        '<div><label for="ip">Adresse IP ou plage CIDR</label>'
        '<input type="text" id="ip" name="ip" placeholder="93.184.216.0/24" '
        'autocomplete="off" required></div>'
        "</div>"
        '<button type="submit" class="principal">Ajouter au registre</button>'
        "</form></section>"
    )
