"""Le service web : routes, base de données, démarrage.

Les lectures sont des GET sans effet. Les modifications sont des POST, vérifiés
en origine, et chacune ouvre une transaction qui contient à la fois le
changement et sa ligne d'audit : il n'existe pas de chemin où l'un s'écrit sans
l'autre.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import asyncpg
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route

from . import pages, queries
from .config import (
    ConfigurationInvalide,
    Settings,
    identity_environment_defaults,
    load_settings,
)
from .http_guard import OrigineRefusee, check_same_origin, client_ip, parse_form
from .naming import (
    SaisieInvalide,
    clamp_limit,
    normalize_address_list,
    normalize_admin_email,
    normalize_base_url,
    normalize_email_address,
    normalize_fqdn,
    normalize_hostile_network,
    normalize_identifier,
    normalize_model_name,
    normalize_preset,
    normalize_quota,
    normalize_role,
    normalize_sender_address,
)
from .presets import PRESETS, secret_filename_for
from .reference import lire_reference
from .secrets import write_named_secret

logger = logging.getLogger("sentimail_admin")

MAX_MESSAGES = 500
MAX_EVENEMENTS = 200
MAX_RETOURS = 200


def _settings(request: Request) -> Settings:
    return request.app.state.settings


async def _fetch(request: Request, query: queries.Query) -> list[dict[str, Any]]:
    rows = await request.app.state.pool.fetch(query.sql, *query.params)
    return [dict(row) for row in rows]


def _avis(request: Request) -> str | None:
    valeur = request.query_params.get("avis")
    return valeur if valeur in pages.AVIS else None


# --- Lectures ---------------------------------------------------------------


async def accueil(request: Request) -> Response:
    return RedirectResponse("/domaines", status_code=302)


async def domaines(request: Request) -> Response:
    lignes = await _fetch(request, queries.list_domains())
    corps = pages.page_domaines(lignes)
    return HTMLResponse(pages.document("Domaines", "/domaines", corps, _avis(request)))


async def etat(request: Request) -> Response:
    settings = _settings(request)
    limite = clamp_limit(
        request.query_params.get("limite"),
        default=settings.events_limit,
        maximum=MAX_EVENEMENTS,
    )
    moteur = await _fetch(request, queries.role_providers())
    routage = await _fetch(request, queries.list_local_routing())
    composants = await _fetch(request, queries.operational_status())
    evenements = await _fetch(request, queries.operational_events(limite))
    # L'encart de confidentialité en tête : où part le contenu du courrier
    # est ce qu'on veut voir avant l'état technique, pas après.
    corps = pages.encart_confidentialite(moteur, routage) + pages.page_etat(
        composants, evenements
    )
    return HTMLResponse(pages.document("État du système", "/etat", corps))


async def courrier(request: Request) -> Response:
    settings = _settings(request)
    limite = clamp_limit(
        request.query_params.get("limite"),
        default=settings.messages_limit,
        maximum=MAX_MESSAGES,
    )
    # Une référence citée réduit la liste au dossier nommé ; sans elle, la
    # page reste le fil du courrier récent.
    citation = lire_reference(request.query_params.get("ref"))
    empreinte = citation[1] if citation and citation[0] == "M" else ""
    cite = f"M-{empreinte}" if empreinte else ""
    messages = await _fetch(request, queries.recent_messages(limite, empreinte))
    corps = pages.page_courrier(messages, limite, cite)
    return HTMLResponse(
        pages.document("Courrier récent", "/courrier", corps, _avis(request))
    )


async def mesure(request: Request) -> Response:
    """Ce que la chaine decide, et ce qu'elle se trompe de decider.

    La console n'embarque pas le collector : elle lit le rapport deja publie,
    exactement comme la page d'etat lit les compteurs du superviseur.
    """
    lignes = await _fetch(request, queries.evaluation_report())
    ligne = lignes[0] if lignes else {}
    rapport = ligne.get("details")
    if isinstance(rapport, str):
        try:
            rapport = json.loads(rapport)
        except ValueError:
            rapport = None
    corps = pages.page_mesure(rapport, ligne.get("observed_at"))
    return HTMLResponse(pages.document("Mesure d'efficacite", "/mesure", corps))


async def apprentissage(request: Request) -> Response:
    destinataires = await _fetch(request, queries.learning_participants())
    selection = (request.query_params.get("destinataire") or "").strip().casefold()
    regles: list[dict[str, Any]] = []
    retours: list[dict[str, Any]] = []
    connus = {str(ligne["email"]) for ligne in destinataires}
    if selection not in connus:
        selection = ""
    recherche = (request.query_params.get("q") or "").strip()[:80]
    if selection:
        regles = await _fetch(
            request, queries.participant_policies(selection, recherche)
        )
        retours = await _fetch(
            request, queries.participant_labels(selection, MAX_RETOURS)
        )
    corps = pages.page_apprentissage(
        destinataires, selection or None, regles, retours, recherche
    )
    return HTMLResponse(
        pages.document("Registre d'apprentissage", "/apprentissage", corps)
    )


MAX_ECARTS = 200


async def ecarts(request: Request) -> Response:
    """Les désaccords humain/modèle, à instruire comme des vulnérabilités."""
    vue_traites = request.query_params.get("vue") == "traites"
    citation = lire_reference(request.query_params.get("ref"))
    empreinte = citation[1] if citation and citation[0] == "E" else ""
    cite = f"E-{empreinte}" if empreinte else ""
    metriques = await _fetch(request, queries.discrepancy_metrics())
    lignes = await _fetch(
        request,
        queries.discrepancy_by_reference(empreinte, MAX_ECARTS)
        if empreinte
        else queries.list_discrepancies(vue_traites, MAX_ECARTS),
    )
    corps = pages.page_ecarts(metriques, lignes, vue_traites, cite)
    return HTMLResponse(
        pages.document("Écarts humain/modèle", "/ecarts", corps, _avis(request))
    )


async def traiter_ecart(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    identifiant = (champs.get("id") or "").strip()
    if not identifiant:
        return _retour("ecart_inconnu", chemin="/ecarts")
    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        acquittement = queries.acknowledge_discrepancy(identifiant, appelant)
        try:
            ligne = await connection.fetchrow(acquittement.sql, *acquittement.params)
        except asyncpg.exceptions.DataError:
            return _retour("ecart_inconnu", chemin="/ecarts")
        if ligne is None:
            return _retour("ecart_inconnu", chemin="/ecarts")
        await _tracer(
            connection,
            action="admin.discrepancy_acknowledged",
            target=identifiant,
            appelant=appelant,
            request=request,
            details={"discrepancy_id": identifiant},
        )
    logger.info("écart traité id=%s par=%s", identifiant, appelant)
    return _retour("ecart_traite", chemin="/ecarts")


async def aller(request: Request) -> Response:
    """Ouvre le dossier cité par sa référence, quelle que soit sa famille.

    Une référence circule dans des échanges, des notes, des courriers ; celui
    qui la colle ne sait pas forcément sur quelle page elle vit. La console le
    sait, elle : la lettre dit la famille, et la famille dit la page.
    """
    citation = lire_reference(request.query_params.get("ref"))
    if citation is None:
        return _retour("reference_illisible", chemin="/ecarts")
    famille, empreinte = citation
    if famille == "M":
        return RedirectResponse(f"/courrier?ref=M-{empreinte}", status_code=303)
    if famille == "E":
        return RedirectResponse(f"/ecarts?ref=E-{empreinte}", status_code=303)
    # « D- » vit dans une lettre, pas dans une table : on le dit plutôt que
    # de faire chercher la console au hasard.
    return _retour("reference_courrier", chemin="/ecarts")


async def sante(request: Request) -> Response:
    await request.app.state.pool.fetchval("SELECT 1")
    return PlainTextResponse("ok")


async def sante_pipeline(request: Request) -> Response:
    """La santé de bout en bout du pipeline, telle que la sonde l'a mesurée.

    `/sante` dit que le service web répond ; ceci dit qu'un vrai message entre
    encore dans le pipeline et y est capturé. Le signal vient du superviseur,
    qui l'écrit à chaque cycle dans operational_status ; on le rend ici sous une
    forme qu'une sonde centrale consomme : 200 tant que le dernier passage a
    réussi, 503 quand un message n'entre plus. Un état non encore mesuré n'est
    pas une panne - la sonde vient peut-être de démarrer.
    """
    row = await request.app.state.pool.fetchrow(
        "SELECT details, observed_at FROM operational_status "
        "WHERE component='sentimail-v3'"
    )
    details = (row["details"] if row else None) or {}
    if isinstance(details, str):
        details = json.loads(details)
    mail_e2e = details.get("mail_e2e") or {"status": "unknown"}
    status = str(mail_e2e.get("status", "unknown"))
    body = {
        "mail_e2e": mail_e2e,
        "observed_at": row["observed_at"].isoformat() if row else None,
    }
    return JSONResponse(body, status_code=503 if status == "down" else 200)


async def reglages(request: Request) -> Response:
    domaines = await _fetch(request, queries.list_quotas())
    routage = await _fetch(request, queries.list_local_routing())
    moteur = await _fetch(request, queries.role_providers())
    identite = await _fetch(request, queries.instance_identity_row())
    settings = _settings(request)

    # Un lien de préréglage ne fait que préremplir le formulaire d'UN rôle :
    # une entrée invalide ou incomplète dans la requête est ignorée en
    # silence plutôt que refusée, comme le tri par recherche ailleurs dans
    # cette console.
    preset_choisi: dict[str, str] = {}
    role_qp = request.query_params.get("role")
    preset_qp = request.query_params.get("preset")
    if role_qp in ("verdict", "conversation") and preset_qp in PRESETS:
        preset_choisi[role_qp] = preset_qp

    connu = {str(ligne["role"]): ligne for ligne in moteur}
    for role in ("verdict", "conversation"):
        ligne = connu.get(role)
        preregle = pages.preset_effectif(role, ligne, preset_choisi)
        fichier_cible = secret_filename_for(preregle, role)
        # Seule l'existence du fichier est constatée, jamais son contenu :
        # c'est ce qui dit au formulaire s'il peut proposer de garder la clé
        # déjà posée plutôt que d'en exiger une nouvelle.
        pose = Path(settings.provider_secrets_dir, fichier_cible).exists()
        if ligne is not None:
            ligne["secret_pose"] = pose
        else:
            connu[role] = {"role": role, "secret_pose": pose}
    moteur = list(connu.values())

    corps = (
        pages.page_reglages_moteur(moteur, routage, preset_choisi)
        + pages.encart_confidentialite(moteur, routage)
        + pages.page_reglages_identite(
            identite[0] if identite else None, identity_environment_defaults()
        )
        + pages.page_reglages(domaines, routage)
    )
    return HTMLResponse(
        pages.document("Réglages", "/reglages", corps, _avis(request))
    )


# --- Modifications ----------------------------------------------------------


async def _lire_formulaire(request: Request) -> tuple[dict[str, str], str]:
    """Vérifie l'origine, puis renvoie le formulaire et l'IP de l'appelant."""
    settings = _settings(request)
    check_same_origin(request.headers, settings.trusted_origins)
    champs = parse_form(request.headers.get("content-type"), await request.body())
    appelant = client_ip(
        request.client.host if request.client else None,
        request.headers,
        settings.trusted_proxies,
    )
    return champs, appelant


async def _tracer(
    connection: asyncpg.Connection[Any],
    *,
    action: str,
    target: str,
    appelant: str,
    request: Request,
    details: dict[str, Any] | None = None,
) -> None:
    entree = queries.audit_entry(
        action=action,
        target=target,
        client_ip=appelant,
        user_agent=request.headers.get("user-agent"),
        details=details,
    )
    await connection.execute(entree.sql, *entree.params)


async def ajouter_domaine(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    fqdn = normalize_fqdn(champs.get("fqdn"))
    admin_email = normalize_admin_email(champs.get("admin_email"))

    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        insertion = queries.insert_domain(fqdn, admin_email)
        ligne = await connection.fetchrow(insertion.sql, *insertion.params)
        if ligne is None:
            return _retour("domaine_existant")
        # Le changement et sa trace partagent la même transaction : aucun des
        # deux ne peut être écrit sans l'autre.
        await _tracer(
            connection,
            action="admin.domain_added",
            target=fqdn,
            appelant=appelant,
            request=request,
            details={"status": "pending", "admin_email": admin_email},
        )
    logger.info("domaine ajouté fqdn=%s par=%s", fqdn, appelant)
    return _retour("domaine_ajoute")


async def activer_domaine(request: Request) -> Response:
    return await _changer_etat(
        request,
        query=queries.activate_domain,
        action="admin.domain_activated",
        avis="domaine_active",
    )


async def suspendre_domaine(request: Request) -> Response:
    return await _changer_etat(
        request,
        query=queries.suspend_domain,
        action="admin.domain_suspended",
        avis="domaine_suspendu",
    )


async def enregistrer_plafonds(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    identifiant = normalize_identifier(champs.get("domaine"))
    plafonds = {
        "assistant_hourly": normalize_quota(champs.get("assistant_horaire")),
        "assistant_daily": normalize_quota(champs.get("assistant_quotidien")),
        "verdict_hourly": normalize_quota(champs.get("verdict_horaire")),
        "verdict_daily": normalize_quota(champs.get("verdict_quotidien")),
    }
    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        mutation = queries.update_quotas(identifiant, *plafonds.values())
        ligne = await connection.fetchrow(mutation.sql, *mutation.params)
        if ligne is None:
            return _retour("domaine_inconnu", "/reglages")
        await _tracer(
            connection,
            action="admin.domain_quotas_changed",
            target=str(ligne["fqdn"]),
            appelant=appelant,
            request=request,
            details=plafonds,
        )
    logger.info("plafonds modifiés fqdn=%s par=%s", ligne["fqdn"], appelant)
    return _retour("plafonds_enregistres", "/reglages")


async def enregistrer_moteur(request: Request) -> Response:
    """Enregistre le moteur d'UN rôle : chacun choisit le sien.

    Le préréglage choisi ne fixe que l'adaptateur (``provider``), le
    paramètre de longueur et le fichier où la clé se pose - l'adresse et le
    modèle restent modifiables par l'opérateur, y compris pour un préréglage
    nommé (une même API peut exposer plusieurs déploiements ou versions).

    La clé est facultative pour un point d'accès local (``ollama``,
    ``custom``) : si le champ est vide et qu'aucun fichier n'existe encore
    pour ce rôle, l'enregistrement est accepté quand même - un fichier absent
    se lit comme une clé vide côté service, ce qui est la bonne
    représentation d'un point d'accès qui n'en exige pas. Pour tout autre
    préréglage, une clé est exigée tant qu'aucune n'a jamais été posée. Un
    envoi sans clé alors qu'un fichier est déjà posé le laisse intact :
    ``write_named_secret`` n'est alors jamais appelé.
    """
    champs, appelant = await _lire_formulaire(request)
    role = normalize_role(champs.get("role"))
    preregle = normalize_preset(champs.get("preset"))
    base_url = normalize_base_url(champs.get("base_url"))
    modele = normalize_model_name(champs.get("modele"))
    configuration = PRESETS[preregle]
    fichier = secret_filename_for(preregle, role)

    settings = _settings(request)
    cle = str(champs.get("cle") or "").strip()
    if cle:
        try:
            write_named_secret(settings.provider_secrets_dir, fichier, cle)
        except ValueError as exc:
            raise SaisieInvalide(str(exc)) from exc
    else:
        pose = Path(settings.provider_secrets_dir, fichier).exists()
        if not pose and preregle not in ("ollama", "custom"):
            raise SaisieInvalide(
                "Indiquez une clé : ce fournisseur n'en a encore aucune posée."
            )
        # Sinon : soit le fichier existant est conservé tel quel (aucune
        # écriture), soit le point d'accès est local et n'en a pas besoin.

    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        mutation = queries.set_role_provider(
            role,
            configuration.provider,
            base_url,
            modele,
            configuration.token_limit_param,
            fichier,
            configuration.body_extras,
            appelant,
        )
        await connection.fetchrow(mutation.sql, *mutation.params)
        await _tracer(
            connection,
            action="admin.role_provider_changed",
            target=role,
            appelant=appelant,
            request=request,
            details={
                "provider": configuration.provider,
                "base_url": base_url,
                "model": modele,
            },
        )
    logger.info(
        "moteur du rôle %s modifié préregle=%s par=%s", role, preregle, appelant
    )
    return _retour("moteur_enregistre", "/reglages")


async def enregistrer_identite(request: Request) -> Response:
    """Enregistre l'identité de l'instance : un singleton, comme le moteur.

    Une table vide n'est pas relue à la volée par les autres services : dès
    que cette ligne existe, ils la préfèrent à leur environnement. Le geste
    « Reprendre la main » soumet ce même formulaire, prérempli des valeurs
    d'environnement affichées : le premier enregistrement copie donc
    exactement ce qui s'appliquait déjà, rien ne change en silence.
    """
    champs, appelant = await _lire_formulaire(request)
    adresse = normalize_email_address(champs.get("action_address"))
    alias = normalize_address_list(champs.get("action_aliases"))
    expediteur = normalize_sender_address(champs.get("assistant_sender"))
    sonde = normalize_email_address(champs.get("probe_recipient"))

    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        mutation = queries.set_instance_identity(
            adresse, alias, expediteur, sonde, appelant
        )
        await connection.fetchrow(mutation.sql, *mutation.params)
        # Rien de sensible ici : ce sont des adresses de service, pas des
        # secrets - elles peuvent figurer dans la trace d'audit sans réserve.
        await _tracer(
            connection,
            action="admin.identity_changed",
            target=adresse,
            appelant=appelant,
            request=request,
            details={
                "action_address": adresse,
                "action_aliases": alias,
                "assistant_sender": expediteur,
                "probe_recipient": sonde,
            },
        )
    logger.info("identité de l'instance modifiée par=%s", appelant)
    return _retour("identite_enregistree", "/reglages")


async def enregistrer_modele(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    role = normalize_role(champs.get("role"))
    modele = normalize_model_name(champs.get("modele"))
    actif = str(champs.get("etat") or "").strip() == "local"
    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        mutation = queries.set_local_routing(role, modele, actif)
        ligne = await connection.fetchrow(mutation.sql, *mutation.params)
        await _tracer(
            connection,
            action="admin.local_model_changed",
            target=role,
            appelant=appelant,
            request=request,
            details={"model": modele, "enabled": actif},
        )
    logger.info(
        "modèle %s rôle=%s modèle=%s par=%s",
        "activé" if actif else "retiré",
        role,
        modele,
        appelant,
    )
    return _retour("modele_enregistre" if actif else "modele_retire", "/reglages")


async def _changer_etat(
    request: Request, *, query: Any, action: str, avis: str
) -> Response:
    champs, appelant = await _lire_formulaire(request)
    identifiant = normalize_identifier(champs.get("domaine"))

    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        mutation = query(identifiant)
        ligne = await connection.fetchrow(mutation.sql, *mutation.params)
        if ligne is None:
            # L'activation exige une preuve de maîtrise : sans elle la
            # requête ne touche aucune ligne, comme pour un domaine absent.
            # Les deux refus n'ont pas le même remède, ils ne se disent pas
            # avec la même phrase.
            connu = await connection.fetchval(
                "SELECT verified_at IS NULL FROM domains WHERE id = $1",
                identifiant,
            )
            return _retour(
                "domaine_non_verifie" if connu else "domaine_inconnu"
            )
        await _tracer(
            connection,
            action=action,
            target=str(ligne["fqdn"]),
            appelant=appelant,
            request=request,
            details={"domain_id": identifiant, "status": str(ligne["status"])},
        )
    logger.info("%s fqdn=%s par=%s", action, ligne["fqdn"], appelant)
    return _retour(avis)


def _retour(avis: str, chemin: str = "/domaines") -> Response:
    """Après une modification, on renvoie vers une page : jamais de re-POST.

    On revient là d'où la modification a été demandée, sinon l'avis s'affiche
    sur un écran qui n'a rien à voir avec ce qu'on vient de changer.
    """
    return RedirectResponse(f"{chemin}?avis={avis}", status_code=303)


# --- Erreurs ----------------------------------------------------------------


async def sources(request: Request) -> Response:
    recherche = (request.query_params.get("q") or "").strip()[:80]
    lignes = await _fetch(request, queries.list_hostile_sources(recherche))
    actives = await _fetch(request, queries.count_active_hostile_sources())
    corps = pages.page_sources(
        lignes, int(actives[0]["actives"]) if actives else 0, recherche
    )
    return HTMLResponse(
        pages.document("Sources hostiles", "/sources", corps, _avis(request))
    )


async def ajouter_source(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    network = normalize_hostile_network(champs.get("ip"))
    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        insertion = queries.insert_hostile_source(network)
        ligne = await connection.fetchrow(insertion.sql, *insertion.params)
        if ligne is None:
            return _retour("source_existante", chemin="/sources")
        await _tracer(
            connection,
            action="admin.hostile_source_added",
            target=network,
            appelant=appelant,
            request=request,
            details={"network": network},
        )
    logger.info("source hostile ajoutée ip=%s par=%s", network, appelant)
    return _retour("source_ajoutee", chemin="/sources")


async def supprimer_source(request: Request) -> Response:
    champs, appelant = await _lire_formulaire(request)
    network = normalize_hostile_network(champs.get("ip"))
    async with (
        request.app.state.pool.acquire() as connection,
        connection.transaction(),
    ):
        suppression = queries.delete_hostile_source(network)
        ligne = await connection.fetchrow(suppression.sql, *suppression.params)
        if ligne is None:
            return _retour("source_inconnue", chemin="/sources")
        await _tracer(
            connection,
            action="admin.hostile_source_removed",
            target=network,
            appelant=appelant,
            request=request,
            details={"network": network},
        )
    logger.info("source hostile retirée ip=%s par=%s", network, appelant)
    return _retour("source_supprimee", chemin="/sources")


async def erreur_saisie(request: Request, exc: Exception) -> Response:
    return HTMLResponse(pages.page_erreur("Saisie refusée", str(exc)), status_code=400)


async def erreur_origine(request: Request, exc: Exception) -> Response:
    logger.warning(
        "requête refusée origine=%r hôte=%r pair=%r",
        request.headers.get("origin"),
        request.headers.get("host"),
        request.client.host if request.client else None,
    )
    return HTMLResponse(pages.page_erreur("Requête refusée", str(exc)), status_code=403)


# --- Assemblage -------------------------------------------------------------

routes = [
    Route("/", accueil),
    Route("/domaines", domaines),
    Route("/domaines/ajouter", ajouter_domaine, methods=["POST"]),
    Route("/domaines/activer", activer_domaine, methods=["POST"]),
    Route("/domaines/suspendre", suspendre_domaine, methods=["POST"]),
    Route("/etat", etat),
    Route("/courrier", courrier),
    Route("/aller", aller),
    Route("/mesure", mesure),
    Route("/ecarts", ecarts),
    Route("/ecarts/traiter", traiter_ecart, methods=["POST"]),
    Route("/apprentissage", apprentissage),
    Route("/sante", sante),
    Route("/sante/pipeline", sante_pipeline),
    Route("/sources", sources),
    Route("/sources/ajouter", ajouter_source, methods=["POST"]),
    Route("/sources/supprimer", supprimer_source, methods=["POST"]),
    Route("/reglages", reglages),
    Route("/reglages/plafonds", enregistrer_plafonds, methods=["POST"]),
    Route("/reglages/modele", enregistrer_modele, methods=["POST"]),
    Route("/reglages/moteur", enregistrer_moteur, methods=["POST"]),
    Route("/reglages/identite", enregistrer_identite, methods=["POST"]),
]


def create_app(settings: Settings) -> Starlette:
    @asynccontextmanager
    async def lifespan(app: Starlette):  # type: ignore[no-untyped-def]
        pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=4)
        app.state.pool = pool
        app.state.settings = settings
        try:
            yield
        finally:
            await pool.close()

    return Starlette(
        routes=routes,
        lifespan=lifespan,
        exception_handlers={
            SaisieInvalide: erreur_saisie,
            OrigineRefusee: erreur_origine,
        },
    )


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    try:
        settings = load_settings()
    except ConfigurationInvalide as error:
        raise SystemExit(f"Configuration refusée : {error}") from error

    logger.info(
        "console d'administration sur %s:%s", settings.bind_host, settings.bind_port
    )
    uvicorn.run(
        create_app(settings),
        host=settings.bind_host,
        port=settings.bind_port,
        # Aucun relais n'est présumé : l'IP du pair est celle qu'on inscrit.
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()
