"""L'alerte du superviseur, écrite pour être lue.

Elle partait en JSON brut : « État : OK » suivi de trente compteurs. Lire
« verdict_execution_mismatches:0 » suppose de savoir ce que mesure ce
compteur, et pourquoi zéro est une bonne nouvelle. Comme le rapport
d'entretien, ce module ne mesure rien et ne décide rien : il traduit l'état
déjà constaté en phrases, à la charte des autres surfaces - bandeau coloré,
sections, signature. L'état brut ne part pas par courrier : il vit dans
operational_status et les journaux du superviseur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape

VERT = "#15803d"
AMBRE = "#b45309"
ROUGE = "#b91c1c"
GRIS = "#64748b"
ENCRE = "#0f172a"

# Chaque code de dégradation, dit en français. Un code absent d'ici reste
# montré tel quel : mieux vaut un signal brut qu'un signal tu.
_RAISONS = {
    "core_qualification_lost": (
        "le nouveau cœur est activé sans qualification encore valable ; "
        "les nouvelles captures reviennent sur l’ancien cœur"
    ),
    "core_comparison_mismatches": (
        "la comparaison des deux cœurs a relevé une divergence de jugement"
    ),
    "core_comparison_errors": (
        "une comparaison des deux cœurs ou son audit a échoué"
    ),
    "core_health_unavailable": "le contrôle de la bascule du cœur ne peut plus être lu",
    "analysis_backlog": "des messages attendent leur analyse depuis plus de 10 minutes",
    "delivery_backlog": "des livraisons attendent depuis plus de 5 minutes",
    "outbox_errors": "des courriers de MAIA n’ont pas pu partir",
    "unprotected_holds": "des messages sont retenus sans que leur avis soit parti",
    "silent_holds": "des messages sont retenus en silence",
    "fail_closed_holds": (
        "des messages que le Code tient pour dangereux sont retenus sans avis : "
        "ils ne sont pas livrés en clair"
    ),
    "review_fail_open_last_hour": (
        "des messages retenus ont été livrés en mode de secours, faute d’avis"
    ),
    "junk_envelope_fallbacks_last_hour": (
        "des indésirables sont partis annotés, liens actifs, faute d’enveloppe "
        "neutralisée"
    ),
    "delivered_without_smtp_event": "des livraisons n’ont pas laissé de trace SMTP",
    "smtp_events_without_queue_id": "des envois SMTP n’ont pas d’identifiant de file",
    "accepted_without_terminal_outcome": (
        "des messages acceptés depuis plus de 10 minutes n’ont ni livraison ni avis"
    ),
    "suppressed_without_event": "des blocages demandés n’ont pas laissé leur trace terminale",
    "junk_not_filed": "des indésirables n’ont pas été rangés",
    "missing_deep_hook_runs": "des inspections profondes manquent",
    "coherence_hook_failures": "la vérification du contenu et des destinations rencontre une erreur",
    "verdict_execution_mismatches": "des verdicts n’ont pas été exécutés conformément",
    "sender_relation_silent": (
        "des passages de l’enquêteur qui confronte l’expéditeur au message "
        "sont restés sans constat"
    ),
    "feedback_application_mismatches": (
        "des retours utilisateur n’ont pas produit tous leurs effets attendus"
    ),
    "verdict_provider_credit_exhausted": (
        "le solde du fournisseur du juge est épuisé et ses appels sont refusés"
    ),
    "verdict_retries_overdue": (
        "un nouvel essai d’analyse planifié n’a pas abouti à son échéance"
    ),
    "verdict_retries_exhausted": (
        "des analyses ont échoué à leurs quatre essais espacés sur plus de cinq "
        "heures : leurs messages sont retenus avec un avis au destinataire"
    ),
    "organisation_search_rejected": (
        "le moteur de recherche refuse la clé de SentiMail : les identités "
        "revendiquées ne sont plus confrontées à leurs domaines officiels"
    ),
    "organisation_search_errors_last_hour": (
        "le moteur de recherche a rendu des erreurs sur la dernière heure"
    ),
    "classifier_errors_last_hour": (
        "le classifieur local échoue : le juge distant reprend les dossiers ; "
        "vérifier le modèle avec supervision.classifier --status"
    ),
    "classifier_unsafe_divergences": (
        "le classifieur aurait livré un dossier que le juge distant refuse ; "
        "le modèle doit rester en observation"
    ),
    "classifier_cycle_unhealthy": (
        "le cycle de qualification du classifieur est en échec ou en retard ; "
        "consulter la page Classifieur local et le service caretaker"
    ),
    "retention_overdue": "la purge de rétention est en retard",
    "verdict_errors_last_hour": "des analyses ont échoué sur la dernière heure",
    "hook_errors_last_hour": "des observations ont échoué sur la dernière heure",
    "partial_investigations_last_hour": "des enquêtes sont restées incomplètes sur la dernière heure",
    "missing_required_hook_sets": "des dossiers n’ont pas toutes leurs observations obligatoires",
    "missing_deep_evidence": "des dossiers n’ont pas leurs preuves profondes",
    "sender_domain_enrichment_gaps": "des domaines expéditeurs n’ont pas été enrichis",
    "slow_url_inspections": "des inspections de liens sont trop lentes",
    "external_analysis_service_errors_last_hour": "les services d’analyse ont rendu des erreurs sur la dernière heure",
    "assistant_interpretation_errors_last_hour": "des réponses ont été mal interprétées sur la dernière heure",
    "verdict_llm_hourly_near_limit": "le quota horaire d’appels au juge approche de sa limite",
    "verdict_llm_daily_near_limit": "le quota quotidien d’appels au juge approche de sa limite",
    "backup_stale": "la dernière sauvegarde est trop ancienne",
    "smtp_ingress_preflight_failed": "la porte d’entrée SMTP ne répond plus",
    "smtp_relay_preflight_failed": "le relais de sortie SMTP ne répond plus",
}
_MAIL_E2E = re.compile(r"^mail_e2e_(.+)$")
_ETAPES_TEMOIN = {"send": "envoi", "capture": "capture"}


@dataclass(frozen=True)
class Lettre:
    subject: str
    text: str
    html: str


def _raison(code: str) -> str:
    temoin = _MAIL_E2E.match(code)
    if temoin:
        etape = _ETAPES_TEMOIN.get(temoin.group(1), temoin.group(1))
        return f"le message-témoin est resté à l’étape « {etape} »"
    return _RAISONS.get(code, f"le signal « {code} » est levé")


def _concernes(details: dict[str, object]) -> list[str]:
    """Les messages derrière les dégradations, nommés par leur sujet.

    Une dégradation sans son message ne s'exploite pas ; un identifiant
    interne n'apprend rien. Le sujet, si.
    """
    vus: set[str] = set()
    noms: list[str] = []
    for exemple in details.get("soft_failure_examples") or []:
        if not isinstance(exemple, dict):
            continue
        nom = str(exemple.get("subject") or "").strip() or (
            "message " + str(exemple.get("message_id") or "")[:8]
        )
        if nom in vus:
            continue
        vus.add(nom)
        noms.append(nom)
    return noms[:5]


def _minutes(seconds: object) -> int:
    return max(1, round(float(seconds) / 60))  # type: ignore[arg-type]


_PALIERS = {"economy": "palier économique", "premium": "palier premium"}


def _etape(message: dict[str, object]) -> str:
    """Où le message bloque, dit avec ce que le relevé sait.

    Un appel au modèle encore ouvert est l'étape la plus précise ; sinon le
    dernier run du juge dit s'il instruit, s'il a échoué, ou s'il n'a jamais
    commencé. La lettre ne connaît pas le plafond de tentatives du moteur :
    elle dit l'échec, pas s'il sera rejoué.
    """
    modele = message.get("llm_model")
    if modele:
        texte = f"le juge attend la réponse du modèle {modele}"
        palier = _PALIERS.get(str(message.get("llm_stage") or ""))
        if palier:
            texte += f" ({palier})"
        depuis = message.get("llm_since_seconds")
        if isinstance(depuis, (int, float)):
            texte += f" depuis {_minutes(depuis)} min"
        return texte
    statut = message.get("run_status")
    if statut == "error":
        fois = int(message.get("run_attempts") or 0)  # type: ignore[call-overload]
        erreur = str(message.get("run_error_type") or "erreur inconnue")
        retard = message.get("retry_overdue_seconds")
        if isinstance(retard, (int, float)) and retard > 0:
            return (
                f"le juge a échoué {fois} fois ({erreur}) et le nouvel essai "
                f"prévu il y a {_minutes(retard)} min n’a pas démarré"
            )
        return f"le juge a échoué {fois} fois ({erreur})"
    if statut == "running":
        return "le juge instruit le dossier"
    if message.get("delivery_status") in ("release_pending", "deferred"):
        return "la livraison attend le relais SMTP"
    return "aucun juge ne l’a encore pris : il attend un juge libre"


def _en_attente(details: dict[str, object]) -> list[str]:
    """Les messages derrière les compteurs de retard, un par ligne.

    Le 14 septembre 2026, l'alerte disait « des messages attendent leur
    analyse » sans dire lequel, depuis quand ni où il bloquait. Une
    renotification rejoue un état antérieur qui peut ne pas porter la clé.
    """
    lignes: list[str] = []
    for message in details.get("stalled_messages") or []:  # type: ignore[union-attr]
        if not isinstance(message, dict):
            continue
        sujet = str(message.get("subject") or "").strip() or "un message sans sujet"
        attente = message.get("waiting_seconds")
        depuis = (
            f", accepté il y a {_minutes(attente)} min"
            if isinstance(attente, (int, float))
            else ""
        )
        lignes.append(f"« {sujet} »{depuis} : {_etape(message)}.")
    return lignes[:5]


# Ce que l'exploitant doit faire, quand un code appelle un geste précis. Les
# autres dégradations se résorbent seules ou se diagnostiquent au journal.
_CONSIGNES = {
    "core_qualification_lost": (
        "consulter supervision.core_rollout --status et rétablir une qualification "
        "complète pour le code et le corpus courants avant de réactiver la bascule."
    ),
    "core_comparison_mismatches": (
        "consulter supervision.core_rollout --status et les comparaisons du contexte "
        "courant ; résoudre la divergence avant de reprendre la bascule."
    ),
    "core_comparison_errors": (
        "consulter supervision.core_rollout --status et audit_log "
        "(core.comparison_failed) ; réparer le comparateur ou sa journalisation."
    ),
    "core_health_unavailable": (
        "vérifier la base et le journal du service watchdog : l’état de la bascule "
        "n’a pas pu être contrôlé."
    ),
    "verdict_provider_credit_exhausted": (
        "recréditer le compte du fournisseur du juge ; les verdicts reprennent "
        "seuls ensuite."
    ),
    "backup_stale": "vérifier le service de sauvegarde et sa dernière archive.",
    "verdict_retries_overdue": (
        "vérifier que le service verdict tourne et prend des dossiers (journal "
        "verdict, verdict.processing_started) : le message reste retenu, rien "
        "n’est perdu, l’essai part dès qu’un juge est libre."
    ),
    "verdict_retries_exhausted": (
        "ouvrir le dossier dans la console : le fournisseur du juge n’a pas "
        "répondu pendant plus de cinq heures. Vérifier son état et le journal "
        "du service verdict (verdict.model_call.error)."
    ),
    "organisation_search_rejected": (
        "renouveler la clé du moteur de recherche (fichier "
        "secrets/search_api_key) puis recréer le service verdict ; le signal "
        "retombe seul à la première recherche qui rend au moins un résultat."
    ),
    "sender_relation_silent": (
        "vérifier le service collector : l’enquêteur sender_relation doit "
        "rendre un constat à chaque message, un silence est un contournement."
    ),
    "retention_overdue": "vérifier que le service de rétention tourne.",
    "smtp_ingress_preflight_failed": (
        "vérifier le service collector : tant que la porte SMTP d’entrée ne "
        "répond pas, les expéditeurs réessaient, rien n’est perdu."
    ),
    "smtp_relay_preflight_failed": (
        "vérifier le relais de sortie SMTP (service relay) : mes avis et les "
        "livraisons attendent qu’il réponde."
    ),
    # Un avis épuisé laisse aussi outbox_errors levé tant que personne n'agit :
    # c'est voulu, cette consigne le couvre.
    "fail_closed_holds": (
        "ne pas livrer ces messages en clair. La cause est dans audit_log "
        "(review.fail_closed, delivery.junk_envelope_failed_held) et au journal "
        "du service verdict ou assistant. Le motif enregistré "
        "(review_guard_reason) peut encore porter un nom hérité du fail-open "
        "(par exemple review_notice_delivery_exhausted_fail_open) : c’est le "
        "même déclencheur, seule la décision finale a changé, de la livraison "
        "au maintien en retenue. Un avis jamais parti est retenté seul, trois "
        "fois à dix minutes d’intervalle, une fois la cause réparée ; un avis "
        "épuisé ou une enveloppe en échec attendent un exploitant : relancer "
        "release_original avec le classement du dossier, ou abandonner le "
        "dossier (état ignored). La console n’a pas ce geste."
    ),
    "review_fail_open_last_hour": (
        "vérifier le service assistant et le bac à sable de rendu : un avis "
        "n’a pas pu partir, et le message a été livré selon son classement, "
        "en boîte de réception s’il était douteux, dans Indésirables s’il "
        "était indésirable."
    ),
    "junk_envelope_fallbacks_last_hour": (
        "lire l’erreur dans audit_log (delivery.junk_envelope_fallback) : "
        "l’enveloppe neutralisée n’a pas pu être composée, le message est "
        "parti annoté dans Indésirables."
    ),
}
_CONSIGNE_PAR_DEFAUT = (
    "rien pour l’instant : je t’écris dès que tout est reparti. Sans rémission "
    "sous 30 minutes, ouvrir le journal du service concerné : verdict pour une "
    "analyse, assistant pour un avis, relay pour une livraison."
)


_SORTS = {
    "delivered": "livré",
    "held": "retenu, avis envoyé",
    "suppressed": "bloqué par une règle",
    "consumed": "traité",
    "undeliverable": "impossible à livrer",
}


def _episode(details: dict[str, object]) -> list[str]:
    """Ce que la rémission raconte : la durée, et le sort de ce qui attendait.

    Le mail « c'est reparti » disait tout est reparti, rien d'autre. Le
    lecteur ne savait ni combien de temps ça avait duré, ni si le message
    bloqué avait fini par arriver.
    """
    episode = details.get("episode")
    if not isinstance(episode, dict):
        return []
    lignes: list[str] = []
    duree = episode.get("duration_seconds")
    if isinstance(duree, (int, float)):
        lignes.append(f"L’épisode a duré {_minutes(duree)} min.")
    messages = [m for m in episode.get("messages") or [] if isinstance(m, dict)]
    if messages:
        lignes.append("Ce qui attendait :")
        for message in messages[:5]:
            sujet = str(message.get("subject") or "").strip() or "un message sans sujet"
            statut = str(message.get("delivery_status") or "")
            sort = _SORTS.get(statut, "toujours en attente" if statut else "sort inconnu")
            attente = message.get("waited_seconds")
            duree_attente = (
                f", après {_minutes(attente)} min d’attente"
                if isinstance(attente, (int, float))
                else ""
            )
            lignes.append(f"  - « {sujet} » : {sort}{duree_attente}.")
    return lignes


def _a_faire(codes: list[str]) -> list[str]:
    consignes: list[str] = []
    for code in codes:
        if _MAIL_E2E.match(code):
            consigne = (
                "vérifier la chaîne de capture (service collector) : le "
                "message-témoin n’est pas passé."
            )
        else:
            consigne = _CONSIGNES.get(code, "")
        if consigne and consigne not in consignes:
            consignes.append(consigne)
    return consignes or [_CONSIGNE_PAR_DEFAUT]


def _temoin(details: dict[str, object]) -> str:
    """Ce que la sonde vérifie, et rien de plus.

    Elle envoie un message, confirme sa capture, puis l'efface : le juge ne le
    voit jamais. La lettre disait « envoi, capture, verdict » ; le 14 septembre
    elle affirmait que la chaîne passait pendant que le juge était suspendu.
    """
    e2e = details.get("mail_e2e")
    e2e = e2e if isinstance(e2e, dict) else {}
    if e2e.get("status") == "ok":
        latence = e2e.get("latency_ms")
        duree = f" en {latence:g} ms" if isinstance(latence, (int, float)) else ""
        return (
            f"Le message-témoin a été envoyé et capturé{duree} ; il ne passe "
            "pas devant le juge."
        )
    return "Le message-témoin n’a pas pu être capturé."


def lettre(status: str, details: dict[str, object]) -> Lettre:
    """Compose l'alerte du superviseur, en texte et en page."""
    codes = [str(code) for code in details.get("reasons") or []]
    credit_epuise = "verdict_provider_credit_exhausted" in codes
    if status == "ok":
        subject = "[SentiMail] MAIA est de nouveau opérationnelle"
        entete = "Tout est reparti : la chaîne fonctionne normalement."
        couleur = VERT
    elif credit_epuise:
        subject = "[SentiMail] Crédit du moteur épuisé"
        entete = (
            "Je ne peux plus obtenir de verdict : le solde du fournisseur "
            "du juge est épuisé."
        )
        couleur = ROUGE
    elif status == "down":
        subject = "[SentiMail] Alerte technique MAIA"
        entete = "La capture des messages est en panne."
        couleur = ROUGE
    else:
        subject = "[SentiMail] Alerte technique MAIA"
        entete = "Je fonctionne, mais quelque chose se dégrade."
        couleur = AMBRE

    raisons = [_raison(code) for code in codes]
    temoin = _temoin(details)
    rassurance = (
        "Rien n’attend, rien n’est retenu en silence, aucun avis n’est resté "
        "en souffrance."
        if status == "ok"
        else "Le relais SMTP reste actif : aucun message n’est perdu, la "
        "dégradation se diagnostique sans échec silencieux."
    )

    concernes = _concernes(details) if status != "ok" else []
    en_attente = _en_attente(details) if status != "ok" else []
    consignes = _a_faire(codes) if status != "ok" else []
    episode = _episode(details) if status == "ok" else []
    lignes = [entete, ""]
    if episode:
        lignes.extend(episode)
        lignes.append("")
    if raisons:
        lignes.append("Ce qui se dégrade :")
        lignes.extend(f"  - {phrase}." for phrase in raisons)
        if concernes:
            lignes.append(
                "  Messages concernés : "
                + ", ".join(f"« {nom} »" for nom in concernes)
                + "."
            )
        lignes.append("")
    if en_attente:
        lignes.append("Messages en attente :")
        lignes.extend(f"  - {phrase}" for phrase in en_attente)
        lignes.append("")
    lignes.extend([temoin, ""])
    if consignes:
        lignes.append("À faire :")
        lignes.extend(f"  - {phrase}" for phrase in consignes)
        lignes.append("")
    # L'état complet vit dans operational_status et les journaux du
    # superviseur : le courrier reste entièrement rédigé.
    lignes.extend([rassurance, "", "— MAIA, ton assistante SentiMail"])

    blocs = [
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;'
        f'margin:0 auto;color:{ENCRE}">'
        f'<div style="background:{couleur};color:#ffffff;padding:12px 14px;'
        'border-radius:10px;font-size:14px;font-weight:bold">'
        f"{escape(entete)}</div>"
    ]
    if raisons:
        puces = "".join(
            f'<li style="margin:0 0 6px 0;line-height:1.4">{escape(phrase)}.</li>'
            for phrase in raisons
        )
        noms = (
            '<div style="margin-top:6px;font-size:13px;color:#475569">'
            "Messages concernés : "
            + ", ".join(f"« {escape(nom)} »" for nom in concernes)
            + ".</div>"
            if concernes
            else ""
        )
        blocs.append(
            '<div style="margin-top:14px">'
            f'<div style="font-size:13px;font-weight:bold;color:{AMBRE};'
            'margin-bottom:6px">Ce qui se dégrade</div>'
            f'<ul style="margin:0;padding-left:18px;font-size:14px;color:{ENCRE}">'
            f"{puces}</ul>{noms}</div>"
        )
    if episode:
        blocs.append(
            '<div style="margin-top:14px">'
            f'<div style="font-size:13px;font-weight:bold;color:{VERT};'
            'margin-bottom:6px">Ce qui s’est passé</div>'
            f'<div style="font-size:14px;color:{ENCRE};line-height:1.45">'
            + "<br>".join(escape(phrase.strip()) for phrase in episode)
            + "</div></div>"
        )
    if en_attente:
        blocs.append(
            '<div style="margin-top:14px">'
            f'<div style="font-size:13px;font-weight:bold;color:{AMBRE};'
            'margin-bottom:6px">Messages en attente</div>'
            f'<ul style="margin:0;padding-left:18px;font-size:14px;color:{ENCRE}">'
            + "".join(
                f'<li style="margin:0 0 6px 0;line-height:1.4">{escape(phrase)}</li>'
                for phrase in en_attente
            )
            + "</ul></div>"
        )
    blocs.append(
        f'<div style="margin-top:14px;font-size:14px;color:{ENCRE};'
        f'line-height:1.45">{escape(temoin)}</div>'
    )
    if consignes:
        blocs.append(
            '<div style="margin-top:14px">'
            f'<div style="font-size:13px;font-weight:bold;color:{ENCRE};'
            'margin-bottom:6px">À faire</div>'
            f'<ul style="margin:0;padding-left:18px;font-size:14px;color:{ENCRE}">'
            + "".join(
                f'<li style="margin:0 0 6px 0;line-height:1.4">{escape(phrase)}</li>'
                for phrase in consignes
            )
            + "</ul></div>"
        )
    blocs.append(
        f'<div style="margin-top:10px;font-size:13px;color:{GRIS};'
        f'line-height:1.45">{escape(rassurance)}</div>'
        '<div style="margin-top:14px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail</div></div>"
    )

    return Lettre(subject, "\n".join(lignes), "".join(blocs))
