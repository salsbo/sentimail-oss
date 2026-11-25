"""Suivi en lecture seule du classifieur, sans dupliquer son garde d'activation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any

from .queries import Query


def status_query() -> Query:
    return Query("""SELECT c.mode,c.model_id,c.updated_at,
        s.details->'classifier' AS report,s.observed_at,
        s.details->>'classifier_errors_last_hour' AS errors,
        s.details->>'classifier_unsafe_divergences' AS downgrades
        FROM classifier_config c LEFT JOIN operational_status s
        ON s.component='sentimail-v3' WHERE c.singleton=true""", ())


def activity_query() -> Query:
    return Query("""SELECT count(*) AS compared,
        count(*) FILTER (WHERE eligible) AS eligible,
        count(*) FILTER (WHERE unsafe) AS unsafe,
        max(o.created_at) AS last_observation,
        (SELECT count(*) FROM verdict_runs v
         WHERE v.status='complete' AND v.completed_at > now()-interval '30 days'
         AND v.response->'api'->>'provider'='local_classifier'
         AND v.response->'api'->>'system_fingerprint'=(SELECT model_id FROM classifier_config WHERE singleton=true)) AS local_verdicts
        FROM classifier_observations o JOIN classifier_config c USING(model_id)
        JOIN verdict_runs r ON r.id=o.verdict_run_id
        WHERE o.created_at > now()-interval '30 days' AND r.status='complete'""", ())


def reasons_query() -> Query:
    return Query("""SELECT reason,count(*) AS total FROM classifier_observations o
        JOIN classifier_config c USING(model_id)
        JOIN verdict_runs r ON r.id=o.verdict_run_id
        WHERE o.created_at > now()-interval '30 days' AND r.status='complete'
        AND NOT eligible GROUP BY reason ORDER BY total DESC,reason""", ())


REASONS = {
    "mixed_evidence": "Indices favorables et défavorables mêlés",
    "adverse_evidence": "Indices défavorables présents",
    "unknown_clue": "Indice absent de l'entraînement",
    "unknown_rules": "Version des règles inconnue",
    "material_danger": "Preuve matérielle de danger",
    "authenticated_hold": "Retenue demandée par l'utilisateur",
    "static_analysis_incomplete": "Analyse statique incomplète",
    "deep_analysis_incomplete": "Analyse profonde incomplète",
    "no_directional_evidence": "Aucun indice orienté",
    "low_probability": "Score inférieur au seuil",
    "truncated_dossier": "Dossier tronqué pour le modèle distant",
    "clue_count_outside_scope": "Nombre d'indices hors du périmètre appris",
}


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return escape(str(value if value is not None else "Non disponible"))


def _date(value: Any) -> str:
    try:
        date = datetime.fromisoformat(value) if isinstance(value, str) else value
        return _text(date.astimezone(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC"))
    except (TypeError, ValueError, AttributeError):
        return "Non disponible"


def page(state: dict[str, Any], activity: dict[str, Any], reasons: list[dict[str, Any]]) -> str:
    mode = state.get("mode", "off")
    label, tone, explanation = {
        "off": ("Désactivé", "neutre", "Le circuit habituel du LLM traite les verdicts."),
        "shadow": ("En observation", "attente", "Le classifieur propose ; le LLM décide. Aucun appel n'est économisé par l'observation."),
        "enforced": ("Décisions locales autorisées", "actif", "Les dossiers simples validés peuvent être tranchés localement. Les autres restent au LLM."),
    }.get(mode, ("État inconnu", "neutre", "La configuration doit être vérifiée."))
    report = _object(state.get("report"))
    observed = state.get("observed_at")
    fresh = isinstance(observed, datetime) and observed.tzinfo is not None and (
        timedelta(0) <= datetime.now(timezone.utc) - observed <= timedelta(minutes=10))
    matching = report.get("model_id") == state.get("model_id")
    usable = bool(report) and fresh and matching and not report.get("error")
    header = (
        '<section><h2>Classifieur local</h2>'
        '<p class="chapeau">Modèle CPU entraîné sur les indices de SentiMail. Suivi en lecture seule.</p>'
        f'<p><span class="etat etat-{tone}">{label}</span></p><p>{explanation}</p>'
        f'<p class="secondaire">Relevé du {_date(observed)}. '
        '<a href="/classifieur">Actualiser</a></p></section>'
    )
    if not state.get("model_id"):
        return header + '<section><p class="vide">Aucun modèle installé.</p></section>'
    warning = "" if usable else (
        '<div class="avis avis-erreur">Rapport de qualification indisponible, périmé ou lié à un autre modèle. '
        'Les mesures d’apprentissage et les conditions d’activation ne sont pas confirmées.</div>')
    compared = int(activity.get("compared") or 0)
    eligible = int(activity.get("eligible") or 0)
    share = f"{eligible / compared:.1%}" if compared else "Pas encore mesurée"
    counts = [
        ("Dossiers comparés", compared), ("Candidats à une décision locale", eligible),
        ("Divergences de livraison", int(activity.get("unsafe") or 0)),
        ("Verdicts locaux sans appel au juge", int(activity.get("local_verdicts") or 0)),
    ]
    metrics = '<section><h2>Activité sur 30 jours</h2><div class="classifier-stats">' + "".join(
        f'<div><span class="secondaire">{title}</span><strong>{_text(value)}</strong></div>'
        for title, value in counts) + '</div>'
    metrics += f'<p>Part éligible parmi les comparaisons : <strong>{share}</strong>.</p>'
    metrics += f'<p class="secondaire">Dernière comparaison : {_date(activity.get("last_observation"))}. '
    metrics += "Mesures du modèle installé. Un verdict local évite l'appel au juge final ; les analyses en amont restent nécessaires.</p></section>"
    metadata = '<section><h2>Modèle installé</h2><table><tbody>'
    values = [("Identifiant", state["model_id"]), ("Méthode", "Régression logistique, scikit-learn"),
              ("Installation / changement de mode", None)]
    for title, value in values:
        rendered = _date(state.get("updated_at")) if value is None else _text(value)
        metadata += f'<tr><th scope="row">{title}</th><td>{rendered}</td></tr>'
    if usable:
        metadata += f'<tr><th>Entraînement</th><td>{_date(report.get("trained_at"))}</td></tr>'
        metadata += f'<tr><th>Seuil de proposition</th><td>{_text(report.get("threshold"))}</td></tr>'
        metadata += f'<tr><th>Juge de référence</th><td>{_text(report.get("reference_model"))}</td></tr>'
    metadata += '</tbody></table></section>'
    learning = ""
    if usable:
        training = _object(report.get("training"))
        learning = '<section><h2>Apprentissage et évaluation</h2>'
        learning += f'<p>{_text(training.get("groups", 0))} groupes appris : '
        learning += f'{_text(training.get("expert_groups", 0))} expertisés et {_text(training.get("teacher_groups", 0))} issus du modèle enseignant ; {_text(training.get("correction_groups", 0))} corrections A/B.</p>'
        learning += '<p class="secondaire">Les corrections A/B sont prioritaires sur les exemples enseignants. '
        learning += 'Un accord avec DeepSeek mesure l’imitation, pas la sécurité.</p>'
        learning += '<table><thead><tr><th>Jeu indépendant</th><th>Groupes</th><th>Candidats</th><th>Livraisons erronées</th></tr></thead><tbody>'
        evaluations = _object(report.get("evaluation"))
        for key, title in (("teacher_valid", "Validation / enseignant"), ("teacher_test", "Test / enseignant"),
                           ("correction_valid", "Validation / corrections A/B"), ("correction_test", "Test / corrections A/B"),
                           ("expert_valid", "Validation / expertise"), ("expert_test", "Test / expertise")):
            row = _object(evaluations.get(key))
            learning += f'<tr><td>{title}</td><td>{_text(row.get("total", 0))}</td><td>{_text(row.get("accepted", 0))}</td>'
            learning += f'<td>{_text(row.get("unsafe", 0)) if row.get("total") else "Non mesuré"}</td></tr>'
        learning += '</tbody></table></section>'
        blockers = report.get("enforcement_blockers")
        learning += '<section><h2>Qualification des décisions locales</h2>'
        if report.get("qualification") == "llm-holdout-ab-1":
            learning += '<p>Qualification sur les verdicts LLM historiques exclus de l’entraînement. Aucune revue humaine obligatoire. '
            learning += 'Contrôle continu par le LLM sur un dossier éligible sur vingt ; tes réponses A/B alimentent les prochains entraînements.</p>'
        if isinstance(blockers, list) and blockers:
            learning += '<p>Conditions encore non remplies :</p><ul>'
            learning += ''.join(f'<li>{_text(item)}</li>' for item in blockers) + '</ul>'
        elif isinstance(blockers, list):
            learning += '<p>Les critères mesurés sont remplis. Le cycle automatique peut autoriser les décisions locales.</p>'
        else:
            learning += '<p class="vide">Qualification non disponible.</p>'
        shadow = _object(report.get("shadow"))
        learning += f'<p class="secondaire">{_text(shadow.get("eligible_groups", 0))} groupes éligibles '
        learning += 'comparés au juge de référence et au prompt courant sur 30 jours.</p></section>'
    reasons_html = '<section><h2>Pourquoi le classifieur s’abstient</h2>'
    if reasons:
        reasons_html += '<table><thead><tr><th>Motif</th><th>Dossiers sur 30 jours</th></tr></thead><tbody>'
        reasons_html += ''.join(f'<tr><td>{_text(REASONS.get(r["reason"], r["reason"]))}</td><td>{_text(r["total"])}</td></tr>' for r in reasons)
        reasons_html += '</tbody></table>'
    else:
        reasons_html += '<p class="vide">Aucune abstention enregistrée sur cette période.</p>'
    reasons_html += '</section>'
    health = '<section><h2>Exploitation</h2>'
    health += f'<p>Erreurs techniques sur une heure : {_text(state.get("errors"))}. '
    health += f'Retours automatiques en observation sur 24 heures : {_text(state.get("downgrades"))}.</p>'
    health += '<p><a href="/etat">Voir l’état du système</a> · <a href="/apprentissage">Voir les retours utilisateur</a></p></section>'
    return header + warning + metrics + metadata + learning + reasons_html + health
