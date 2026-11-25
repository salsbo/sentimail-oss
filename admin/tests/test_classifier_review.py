import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from sentimail_admin.classifier_review import lifecycle_page, sample_page, review_content
from sentimail_admin.app import classifier_review_detail
from sentimail_admin.http_guard import OrigineRefusee


class RevueTests(unittest.TestCase):
    def test_vue_canonique_prioritaire_sur_mime_alternatif_et_echappee(self):
        row = self.row(body_text="BRUIT NON VISIBLE", body_html="<p>616 Consulter</p>",
                       visible_content={"version": "sentimail-visible-content-1",
                           "source": "html_visible_text", "text": "616 Consulter <script>",
                           "truncated": False})
        html = sample_page(row)
        self.assertNotIn("BRUIT NON VISIBLE", html)
        self.assertIn("616 Consulter &lt;script&gt;", html)
        self.assertIn("sentimail-visible-content-1", html)
        self.assertIn('<option value="legitimate">', html)

    def test_ancien_html_signale_et_ne_permet_pas_legitime(self):
        row = self.row(body_text="Alternative texte", body_html='<p>Visible</p><div style="display:none">MASQUE</div>')
        html = sample_page(row)
        self.assertIn("Ancien message sans vue canonique", html)
        self.assertIn("Version texte brut", html)
        self.assertIn("Secours du HTML visible", html)
        self.assertNotIn("MASQUE", html)
        self.assertNotIn('<option value="legitimate">', html)

    def test_ancien_texte_seul_reste_qualifiable_et_vue_expiree_inutilisable(self):
        self.assertFalse(review_content(self.row())[1])
        self.assertIn('<option value="legitimate">', sample_page(self.row()))
        row = self.row(visible_content={"version": "sentimail-visible-content-1",
            "source": "text/plain", "text": "ancien contenu", "truncated": False},
            redacted_at="2026-10-30")
        self.assertEqual(review_content(row), ("", True))
        self.assertNotIn('<form', sample_page(row))

    def row(self, **changes):
        return {"id": 1, "sample_id": 2, "status": "queued", "dossier": {"clues": []},
                "body_text": "Facture à examiner", "model_classification": "dangerous", **changes}

    def test_revue_aveugle_et_confirmation_non_preselectionnee(self):
        html = sample_page(self.row())
        self.assertNotIn("model_classification", html)
        self.assertIn('value="">Choisir après examen', html)
        self.assertNotIn("checked", html)
        self.assertIn('name="reviewed"', html)
        self.assertIn('method="post"', html)

    def test_contenu_actif_ne_devient_pas_du_html_executable(self):
        html = sample_page(self.row(body_text=None, body_html='<script>steal()</script><p>Texte</p><img src="http://evil">',
                                    from_header='<img onerror="steal()">'))
        self.assertNotIn('<script>', html)
        self.assertNotIn('steal()</script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('Texte', html)

    def test_ocr_est_lisible_et_echappe(self):
        html = sample_page(self.row(body_text=None, extracted=['Appelez pour annuler <script>']))
        self.assertIn('Appelez pour annuler &lt;script&gt;', html)
        self.assertIn('<form', html)

    def test_contenu_expire_ou_revue_deja_soumise_ne_permet_pas_de_saisie(self):
        for row in [self.row(body_text=None), self.row(status="submitted")]:
            self.assertNotIn('<form', sample_page(row))

    def test_vue_incomplete_ne_propose_pas_une_confirmation_legitime(self):
        for row in (self.row(body_text='a' * 20001), self.row(extraction_incomplete=True)):
            html = sample_page(row)
            self.assertIn('Contenu tronqué ou extraction incomplète', html)
            self.assertNotIn('<option value="legitimate">', html)

    def test_candidat_et_exclusions_visibles(self):
        html = lifecycle_page({"enabled": True, "auto_activate": True, "candidate_model_id": "abc",
                               "report": {"candidate_blockers": ["expertise manquante"], "exclusions": {
                                   "mailbox_labels_without_dossier": [1, 2], "preference_conflicts": [3]}}})
        self.assertIn('expertise manquante', html)
        self.assertIn('2 labels sans dossier', html)
        self.assertIn('1 dossiers aux préférences contradictoires', html)


class SoumissionTests(unittest.IsolatedAsyncioTestCase):
    def request(self, body, origin="http://admin.test"):
        pool = SimpleNamespace(fetch=AsyncMock(return_value=[{"id": 1}]))
        return SimpleNamespace(method="POST", path_params={"identifier": 1},
            app=SimpleNamespace(state=SimpleNamespace(pool=pool, settings=SimpleNamespace(
                trusted_origins=("http://admin.test",), trusted_proxies=frozenset()))),
            headers={"host": "admin.test", "origin": origin, "content-type": "application/x-www-form-urlencoded"},
            client=SimpleNamespace(host="127.0.0.1"), body=AsyncMock(return_value=body))

    async def test_origine_externe_refusee_avant_modification(self):
        with self.assertRaises(OrigineRefusee):
            await classifier_review_detail(self.request(b'label=legitimate&reviewed=yes', 'http://evil.test'))

    async def test_sans_confirmation_ou_qualification_pas_d_ecriture(self):
        for body in (b'label=legitimate', b'label=invente&reviewed=yes'):
            response = await classifier_review_detail(self.request(body))
            self.assertEqual(response.status_code, 400)

    async def test_post_forge_ne_confirme_pas_une_vue_incomplete(self):
        request = self.request(b'label=legitimate&reviewed=yes')
        request.app.state.pool.fetch.return_value = [{"extraction_incomplete": True}]
        self.assertEqual((await classifier_review_detail(request)).status_code, 400)
