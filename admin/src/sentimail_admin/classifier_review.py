"""Revue humaine sans afficher la réponse enseignante avant qualification."""

from __future__ import annotations

import json
import re
from html import escape
from html.parser import HTMLParser
from typing import Any

from .queries import Query

REASONS = {"legitimate": "confirmed_legitimate", "spam": "confirmed_spam",
           "suspect": "insufficient_evidence", "dangerous": "confirmed_phishing"}
LABELS = {"legitimate": "Légitime", "spam": "Indésirable", "dangerous": "Fraude ou danger",
          "suspect": "Preuves insuffisantes"}


def lifecycle_query() -> Query:
    return Query("""SELECT a.*,
        (SELECT count(*) FROM classifier_review_queue WHERE status='queued') AS queued,
        (SELECT count(*) FROM classifier_review_queue WHERE status='submitted') AS submitted,
        (SELECT count(*) FROM classifier_review_queue WHERE status='done') AS completed
        FROM classifier_automation a WHERE singleton=true""", ())


def queue_query() -> Query:
    return Query("""SELECT q.id,q.sample_id,q.partition,q.status FROM classifier_review_queue q
        WHERE q.status IN ('queued','submitted')
        ORDER BY (q.status='submitted'),(q.partition='test' AND q.eligible) DESC,
          (q.partition='valid' AND q.eligible) DESC,(q.partition='test') DESC,q.id LIMIT 50""", ())


def sample_query(identifier: int) -> Query:
    return Query("""SELECT q.id,q.status,q.sample_id,q.partition,t.dossier,
        m.subject,m.from_header,m.body_text,m.body_html,m.redacted_at,
        m.facts->'visible_content' AS visible_content,
        (SELECT jsonb_agg(e.result->>'extracted_text') FROM external_analyses e
         WHERE e.message_id=m.id AND nullif(e.result->>'extracted_text','') IS NOT NULL) AS extracted,
        EXISTS(SELECT 1 FROM external_analyses e WHERE e.message_id=m.id AND e.subject_kind='attachment'
          AND (e.result->>'extracted_text_truncated'='true' OR e.result->>'extracted_text_incomplete'='true'
               OR e.result->>'analysis_incomplete'='true')) AS extraction_incomplete
        FROM classifier_review_queue q JOIN training_samples t ON t.id=q.sample_id
        LEFT JOIN messages m ON m.id=t.message_id WHERE q.id=$1""", (identifier,))


def lifecycle_page(row: dict[str, Any]) -> str:
    from .classifier import _date, _object, _text
    result = _object(row.get("report"))
    html = '<section><h2>Cycle de qualification</h2>'
    html += f'<p>Entraînement automatique : {"activé" if row.get("enabled") else "désactivé"}. '
    html += f'Activation après qualification : {"autorisée" if row.get("auto_activate") else "manuelle"}.</p>'
    html += f'<p>Dernier cycle terminé : {_date(row.get("last_completed_at"))}. État : {_text(row.get("status"))}.</p>'
    html += '<p>Le cycle passe toutes les six heures et entraîne au plus une fois par jour, sauf nouvelle correction A/B ou revue. '
    html += 'Un candidat corrigé remplace le modèle en cours seulement après avoir réussi son évaluation indépendante.</p>'
    if result.get("error"):
        html += f'<p class="avis avis-erreur">Cycle en échec : {_text(result["error"])}</p>'
    if row.get("candidate_model_id"):
        html += f'<p>Candidat entraîné : {_text(row["candidate_model_id"])}</p>'
        blockers = result.get("candidate_blockers", [])
        html += '<p>Qualification hors ligne du candidat :</p><ul>'
        html += ''.join(f'<li>{_text(v)}</li>' for v in blockers) or '<li>Critères hors ligne remplis ; activation soumise aux contrôles de production.</li>'
        html += '</ul>'
        exclusions = result.get("exclusions", {})
        html += f'<p>Préférences écartées sans être supprimées : {len(exclusions.get("mailbox_labels_without_dossier", []))} labels sans dossier, '
        html += f'{len(exclusions.get("preference_conflicts", []))} dossiers aux préférences contradictoires.</p>'
    html += f'<p>Revues à faire : {_text(row.get("queued", 0))}. Soumises : {_text(row.get("submitted", 0))}. '
    html += f'Intégrées : {_text(row.get("completed", 0))}.</p>'
    return html + '<p><a href="/classifieur/revues">Ouvrir la revue facultative de sécurité</a></p></section>'


def queue_page(rows: list[dict[str, Any]]) -> str:
    html = '<section><h2>Revue de sécurité</h2><p>Qualifier le message après examen des pièces, indépendamment de ce que le modèle aurait répondu. '
    html += 'Cette revue nourrit l’évaluation ; elle ne livre aucun message et ne modifie aucune préférence de boîte.</p>'
    if not rows:
        return html + '<p>Aucun dossier disponible pour une revue.</p></section>'
    html += '<table><thead><tr><th>Échantillon</th><th>Jeu</th><th>État</th></tr></thead><tbody>'
    for row in rows:
        state = "À examiner" if row["status"] == "queued" else "En attente d’intégration"
        html += f'<tr><td><a href="/classifieur/revues/{int(row["id"])}">Échantillon {int(row["sample_id"])}</a></td>'
        html += f'<td>{escape(str(row["partition"]))}</td><td>{state}</td></tr>'
    return html + '</tbody></table><p>50 dossiers au maximum par page. Les groupes déjà expertisés sont retirés de la file au cycle suivant.</p></section>'


VISIBLE_CONTENT_VERSION = "sentimail-visible-content-1"
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_HIDDEN_STYLE = re.compile(r"(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|mso-hide\s*:\s*all|font-size\s*:\s*0(?:px|pt|em|rem|%)?)\s*(?:!important\s*)?(?:;|$)", re.I)


class _Text(HTMLParser):
    """Secours des anciens HTML : sans contenu actif ni blocs inline masqués.

    Il ne prétend pas reproduire le lecteur canonique : cette limite reste
    affichée et interdit de confirmer légitime depuis un ancien HTML.
    """
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.open: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        values = dict(attrs)
        hidden = (any(value for _, value in self.open) or tag in {"head", "script", "style", "template", "svg"}
                  or "hidden" in values or bool(_HIDDEN_STYLE.search(values.get("style") or "")))
        if not hidden and tag in {"p", "br", "div", "tr"}:
            self.parts.append("\n")
        if tag not in _VOID:
            self.open.append((tag, hidden))

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.open)-1, -1, -1):
            if self.open[index][0] == tag:
                del self.open[index:]
                break

    def handle_data(self, data: str) -> None:
        if not any(hidden for _, hidden in self.open):
            self.parts.append(data)


def _visible_view(row: dict[str, Any]) -> dict[str, Any] | None:
    view = row.get("visible_content")
    if isinstance(view, str):
        try:
            view = json.loads(view)
        except ValueError:
            return None
    if (isinstance(view, dict) and view.get("version") == VISIBLE_CONTENT_VERSION
            and isinstance(view.get("text"), str)
            and view.get("source") in {"text/plain", "html_visible_text", "none"}
            and isinstance(view.get("truncated"), bool)):
        return view
    return None


def review_content(row: dict[str, Any]) -> tuple[str, bool]:
    if row.get("redacted_at") is not None:
        return "", True
    view = _visible_view(row)
    html = str(row.get("body_html") or "")
    if view is not None:
        text = view["text"]
        incomplete = view["truncated"]
    else:
        plain = str(row.get("body_text") or "").strip()
        parsed = _Text()
        parsed.feed(html[:100000])
        rendered = ''.join(parsed.parts).strip()
        text = ("Version texte brut :\n" + plain + "\n\nSecours du HTML visible :\n" + rendered
                if plain and html else plain or rendered)
        # Un ancien texte brut seul n'a pas de représentation HTML concurrente.
        incomplete = bool(html)
    extracted = row.get("extracted") or []
    try:
        extracted = json.loads(extracted) if isinstance(extracted, str) else extracted
    except ValueError:
        extracted, incomplete = [], True
    if not isinstance(extracted, list):
        extracted, incomplete = [], True
    text += '\n\n'.join(['', *(str(t) for t in extracted if t is not None)])
    incomplete = bool(incomplete or row.get("extraction_incomplete") or len(text) > 20000)
    return text[:20000], incomplete


def sample_page(row: dict[str, Any]) -> str:
    from .classifier import _object
    text, incomplete = review_content(row)
    has_content = bool(text.strip())
    html = f'<section><h2>Échantillon {int(row["sample_id"])}</h2>'
    html += '<p>Le verdict du modèle est masqué pour cette revue. Les liens et le contenu actif du mail sont désactivés.</p>'
    view = _visible_view(row)
    if view is not None:
        html += f'<p>Texte observé : {escape(view["version"])} ; source {escape(view["source"])}.</p>'
    elif row.get("body_html"):
        html += '<p class="avis avis-erreur">Ancien message sans vue canonique conservée. Les versions MIME sont distinguées ; ce secours HTML ne permet pas de confirmer un message légitime.</p>'
    else:
        html += '<p>Ancien message : version texte brut conservée, sans vue canonique versionnée.</p>'
    html += f'<p>De : {escape(str(row.get("from_header") or "non conservé"))}<br>Objet : {escape(str(row.get("subject") or "non conservé"))}</p>'
    html += f'<pre style="white-space:pre-wrap;overflow-wrap:anywhere">{escape(text[:20000])}</pre>'
    if incomplete:
        html += '<p class="avis avis-erreur">Contenu tronqué ou extraction incomplète : une qualification légitime ne peut pas être confirmée depuis cette vue.</p>'
    clues = _object(row.get("dossier")).get("clues", [])
    html += '<details><summary>Indices du dossier</summary><ul>'
    html += ''.join(f'<li>{escape(str(c.get("clue_code")))} : {escape(str(c.get("direction")))}</li>' for c in clues)
    html += '</ul></details>'
    if row["status"] == "queued" and has_content:
        html += f'<form method="post" action="/classifieur/revues/{int(row["id"])}">'
        html += '<label>Qualification <select name="label" required><option value="">Choisir après examen</option>'
        html += ''.join(f'<option value="{key}">{value}</option>' for key, value in LABELS.items()
                        if not (incomplete and key == "legitimate")) + '</select></label>'
        html += '<label><input type="checkbox" name="reviewed" value="yes" required> J’ai examiné les pièces et je confirme cette qualification de sécurité.</label>'
        html += '<button type="submit">Enregistrer la revue</button></form><p>Intégration au prochain cycle, sous six heures.</p>'
    else:
        html += '<p>Revue déjà soumise, ou contenu expiré : aucune qualification nouvelle ne peut être enregistrée ici.</p>'
    return html + '<p><a href="/classifieur/revues">Retour à la file</a></p></section>'
