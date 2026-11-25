"""Le dossier soumis au juge ne porte que ce qui sert au jugement.

Mesure du 02/09 sur quinze dossiers de production : 60 000 caractères de Code
entier envoyés à chaque appel (la moitié du prompt), 18 000 d'entités pour
l'essentiel redondantes, et seuls les 2 800 tokens du prompt système
profitaient du cache de préfixe DeepSeek.
"""

from __future__ import annotations

import json
import unittest

from sentimail_v3.judgment.verdict_engine import (
    _cited_code_articles,
    _code_index,
    _compact_entities,
    _judgment_rules,
    _ordered_dossier,
    _parse_verdict,
    _prompt,
)


class _Settings:
    auto_delivery_confidence = 0.9


def _articles() -> list[dict[str, object]]:
    return [
        {"article_code": "AUTH-001", "title": "Alignement DMARC", "principle": "p" * 400},
        {"article_code": "AUTH-002", "title": "SPF", "principle": "p" * 400},
        {"article_code": "CONTENT-012", "title": "Écritures mêlées", "principle": "p" * 400},
        {"article_code": "DEEP-013", "title": "Analyse inaboutie", "principle": "p" * 400},
    ]


def _clues() -> list[dict[str, object]]:
    return [
        {"clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001", "direction": "favorable"},
        {"clue_code": "CONTENT_MIXED_SCRIPT", "article_code": "CONTENT-012", "direction": "adverse"},
        {"clue_code": "AUTH_DMARC_PASS", "article_code": "AUTH-001", "direction": "favorable"},
    ]


class CodeArticlesTests(unittest.TestCase):
    def test_seuls_les_articles_declenches_par_un_indice_sont_envoyes(self) -> None:
        retenus = _cited_code_articles(_articles(), _clues())
        self.assertEqual(
            [a["article_code"] for a in retenus], ["AUTH-001", "CONTENT-012"]
        )
        self.assertEqual(len(retenus[0]["principle"]), 400)

    def test_l_index_du_code_reste_complet_mais_tient_en_une_ligne_par_article(self) -> None:
        index = _code_index(_articles())
        self.assertEqual(len(index), 4)
        self.assertEqual(set(index[0]), {"article_code", "title"})
        self.assertEqual(index[3]["article_code"], "DEEP-013")

    def test_le_juge_peut_citer_un_article_de_l_index_sans_etre_rejete(self) -> None:
        """Citer un article du Code qu'aucun indice n'a déclenché, pour dire
        qu'il ne s'applique pas, n'est pas inventer une preuve."""
        dossier: dict[str, object] = {
            "message": {"investigation_status": "complete", "adverse_points": 0},
            "clues": _clues()[:1],
            "code_articles": _cited_code_articles(_articles(), _clues()[:1]),
            "code_index": _code_index(_articles()),
        }
        dossier["judgment_rules"] = _judgment_rules(
            dossier, {"complete": True, "history": {"ground_truth_labels": {}}}, _Settings()
        )
        reponse = {
            "unfavorable": {"clue_codes": [], "arguments": []},
            "favorable": {"clue_codes": ["AUTH_DMARC_PASS"], "arguments": []},
            "final_verdict": {
                "classification": "legitimate",
                "confidence": 0.95,
                "delivery_decision": "deliver",
                "rationale": "DEEP-013 ne s'applique pas : l'analyse est complète.",
                "doubt": False,
                "doubt_reasons": [],
            },
        }
        result = _parse_verdict(json.dumps(reponse), dossier)
        self.assertEqual(result["classification"], "legitimate")

        reponse["final_verdict"]["rationale"] = "AUTH-099 impose la retenue."
        with self.assertRaises(ValueError):
            _parse_verdict(json.dumps(reponse), dossier)


def _row(entity_type: str, value: str, role: str = "mime:0", **extra: object) -> dict[str, object]:
    attributes: object = extra.pop("attributes", None)
    if attributes is None and entity_type == "url":
        attributes = json.dumps(
            {"host": value.split("/")[2], "path": "/x", "query": "", "scheme": "https",
             "fragment": "", "port": None, "password_present": False,
             "username_present": False}
        )
    return {
        "entity_type": entity_type,
        "role": role,
        "value_normalized": value,
        "attributes": attributes,
        "enrichment_status": None,
        "enrichment_source": None,
        "enrichment_data": None,
        **extra,
    }


class EntitiesTests(unittest.TestCase):
    def test_les_attributs_redondants_d_une_url_ne_sont_pas_repetes(self) -> None:
        [entite] = _compact_entities([_row("url", "https://cdn.example.com/a.woff2")])
        self.assertNotIn("attributes", entite)

    def test_un_attribut_qui_dit_quelque_chose_survit(self) -> None:
        attrs = json.dumps({"host": "x.example", "path": "/", "password_present": True})
        [entite] = _compact_entities(
            [_row("url", "https://x.example/", attributes=attrs)]
        )
        self.assertEqual(entite["attributes"], {"password_present": True})

    def test_les_attributs_arrivent_decodes_et_non_en_json_echappe(self) -> None:
        [entite] = _compact_entities(
            [_row("domain", "example.com", attributes=json.dumps({"tld": "com"}))]
        )
        self.assertEqual(entite["attributes"], {"tld": "com"})

    def test_au_dela_de_quatre_urls_par_hote_on_compte_au_lieu_de_lister(self) -> None:
        rows = [_row("url", f"https://cdn.example.com/{i}.png") for i in range(30)]
        rows.append(_row("url", "https://login.evil.example/verify"))
        compact = _compact_entities(rows)
        cdn = [e for e in compact if "cdn.example.com" in str(e["value_normalized"])]
        self.assertEqual(len(cdn), 4)
        self.assertEqual(cdn[-1]["more_urls_same_host"], 26)
        self.assertTrue(
            any("login.evil.example" in str(e["value_normalized"]) for e in compact)
        )

    def test_une_url_de_tracking_interminable_est_coupee(self) -> None:
        [entite] = _compact_entities([_row("url", "https://t.example/?" + "a" * 3000)])
        self.assertLessEqual(len(str(entite["value_normalized"])), 512)


class PromptOrderTests(unittest.TestCase):
    def test_les_sections_constantes_ouvrent_le_dossier(self) -> None:
        """Le cache de préfixe ne sert que si l'invariant précède le variable."""
        dossier = {
            "schema": "s",
            "privacy": {},
            "message": {"subject": "x"},
            "clues": [],
            "code_articles": [],
            "attack_technique_registry": [{"technique_code": "T1"}],
            "code_index": [{"article_code": "AUTH-001", "title": "t"}],
            "judgment_rules": {},
        }
        ordre = list(_ordered_dossier(dossier))
        self.assertEqual(
            ordre[:4], ["schema", "privacy", "attack_technique_registry", "code_index"]
        )
        self.assertEqual(set(ordre), set(dossier))
        contenu = _prompt(dossier)[1]["content"]
        self.assertLess(contenu.index('"code_index"'), contenu.index('"message"'))


if __name__ == "__main__":
    unittest.main()
