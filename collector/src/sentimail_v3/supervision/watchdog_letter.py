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
    "analysis_backlog": "des messages attendent leur analyse depuis trop longtemps",
    "delivery_backlog": "des livraisons attendent",
    "outbox_errors": "des courriers de MAIA n’ont pas pu partir",
    "unprotected_holds": "des messages sont retenus sans que leur avis soit parti",
    "silent_holds": "des messages sont retenus en silence",
    "delivered_without_smtp_event": "des livraisons n’ont pas laissé de trace SMTP",
    "smtp_events_without_queue_id": "des envois SMTP n’ont pas d’identifiant de file",
    "accepted_without_terminal_outcome": "des messages acceptés n’ont pas d’issue finale",
    "junk_not_filed": "des indésirables n’ont pas été rangés",
    "missing_deep_hook_runs": "des inspections profondes manquent",
    "verdict_execution_mismatches": "des verdicts n’ont pas été exécutés conformément",
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


@dataclass(frozen=True)
class Lettre:
    subject: str
    text: str
    html: str


def _raison(code: str) -> str:
    temoin = _MAIL_E2E.match(code)
    if temoin:
        return (
            "le message-témoin n’a pas traversé la chaîne "
            f"(étape « {temoin.group(1)} »)"
        )
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


def _temoin(details: dict[str, object]) -> str:
    e2e = details.get("mail_e2e")
    e2e = e2e if isinstance(e2e, dict) else {}
    if e2e.get("status") == "ok":
        latence = e2e.get("latency_ms")
        duree = f" en {latence:g} ms" if isinstance(latence, (int, float)) else ""
        return (
            "Le message-témoin a traversé toute la chaîne - envoi, capture, "
            f"verdict -{duree}."
        )
    return "Le message-témoin n’a pas pu traverser la chaîne."


def lettre(status: str, details: dict[str, object]) -> Lettre:
    """Compose l'alerte du superviseur, en texte et en page."""
    if status == "ok":
        subject = "[SentiMail] MAIA est de nouveau opérationnelle"
        entete = "Tout est reparti : la chaîne fonctionne normalement."
        couleur = VERT
    elif status == "down":
        subject = "[SentiMail] Alerte technique MAIA"
        entete = "La capture des messages est en panne."
        couleur = ROUGE
    else:
        subject = "[SentiMail] Alerte technique MAIA"
        entete = "Je fonctionne, mais quelque chose se dégrade."
        couleur = AMBRE

    raisons = [_raison(str(code)) for code in details.get("reasons") or []]
    temoin = _temoin(details)
    rassurance = (
        "Rien n’attend, rien n’est retenu en silence, aucun avis n’est resté "
        "en souffrance."
        if status == "ok"
        else "Le relais SMTP reste actif : aucun message n’est perdu, la "
        "dégradation se diagnostique sans échec silencieux."
    )

    concernes = _concernes(details) if status != "ok" else []
    lignes = [entete, ""]
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
    # L'état complet vit dans operational_status et les journaux du
    # superviseur : le courrier reste entièrement rédigé.
    lignes.extend([temoin, "", rassurance, "", "— MAIA, ton assistante SentiMail"])

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
    blocs.append(
        f'<div style="margin-top:14px;font-size:14px;color:{ENCRE};'
        f'line-height:1.45">{escape(temoin)}</div>'
        f'<div style="margin-top:10px;font-size:13px;color:{GRIS};'
        f'line-height:1.45">{escape(rassurance)}</div>'
        '<div style="margin-top:14px;font-size:12px;color:#475569">'
        "— MAIA, ton assistante SentiMail</div></div>"
    )

    return Lettre(subject, "\n".join(lignes), "".join(blocs))
