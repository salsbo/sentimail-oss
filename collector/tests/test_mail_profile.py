"""La mémoire d'une série ne fait confiance ni au nom ni à un relais partagé."""

import json
import unittest
from unittest.mock import AsyncMock, patch

from sentimail_v3.code.mail_profile import mail_profile, profile_history
from sentimail_v3.conversation.human_decision import HumanDecision, apply_human_decision
from sentimail_v3.observation.deep_analysis import _history_signals


def profile(sender="news-123@journal.example.org", **values):
    return mail_profile(sender, **{
        "dmarc": True, "sending_mode": "bulk", "subject": "La lettre du journal",
        **values,
    })


class ProfilTests(unittest.TestCase):
    def test_une_adresse_variable_du_meme_domaine_rejoint_la_meme_serie(self):
        self.assertEqual(profile(), profile("news-456@journal.example.org"))
        self.assertNotEqual(profile(), profile("news-123@autre.example.org"))

    def test_le_type_de_courrier_doit_rester_identique(self):
        self.assertNotEqual(profile(), profile(subject="Facture à régler"))
        self.assertEqual(profile(), profile(subject=" LA  LETTRE DU JOURNAL "))
        self.assertEqual(profile(list_id="<lettre.example.org>"),
                         profile(subject="Lettre du 10 octobre", list_id="<lettre.example.org>"))

    def test_un_nom_affiche_ne_prouve_rien(self):
        self.assertEqual(profile(), profile("Autre marque <news-123@journal.example.org>"))

    def test_pas_de_memoire_sans_dmarc_ni_pour_un_type_inconnu(self):
        self.assertIsNone(profile(dmarc=False))
        self.assertIsNone(profile(sending_mode="unknown"))
        self.assertIsNone(profile(subject=""))
        self.assertIsNone(profile(subject="x" * 301))

    def test_un_relais_ou_une_messagerie_partagee_exige_l_adresse_exacte(self):
        for domain in ("privaterelay.appleid.com", "gmail.com", "sendgrid.net", "client.onmicrosoft.com", "mozmail.com"):
            with self.subTest(domain=domain):
                self.assertNotEqual(profile(f"a@{domain}"), profile(f"b@{domain}"))
                self.assertEqual(profile(f"a@{domain}")["identity_kind"], "sender")

    def test_deux_messages_sans_retour_contraire_donnent_un_indice_du_corpus(self):
        memory = {"profile": profile(), "labels": {"legitimate": 2}}
        signals, _ = _history_signals({"mail_profile_history": memory}, None)
        self.assertTrue(any(s["article_code"] == "HIST-006" for s in signals))
        self.assertFalse(any(s["article_code"] == "POLICY-002" for s in signals))
        for labels in ({"legitimate": 1}, {"legitimate": 3, "dangerous": 1}):
            signals, _ = _history_signals({"mail_profile_history": {"labels": labels}}, None)
            self.assertFalse(any(s["article_code"] == "HIST-006" for s in signals))

    def test_la_memoire_ne_double_pas_le_poids_d_un_expediteur_deja_confirme(self):
        signals, _ = _history_signals({
            "ground_truth_labels": {"legitimate": 6},
            "mail_profile_history": {"labels": {"legitimate": 6}},
        }, None)
        self.assertFalse(any(s["article_code"] == "HIST-006" for s in signals))


class PersistanceTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_memoire_survit_a_la_purge_du_message(self):
        connection = AsyncMock()
        connection.fetch.return_value = []
        decision = HumanDecision(
            message_id="11111111-1111-1111-1111-111111111111",
            participant_email="user@example.net", sender="news@journal.example.org",
            subject="La lettre du journal", classification="legitimate",
        )
        with patch("sentimail_v3.conversation.human_decision.read_mail_profile", AsyncMock(return_value=profile())), patch(
            "sentimail_v3.conversation.human_decision.store_ground_truth_sample", AsyncMock()
        ):
            await apply_human_decision(connection, decision)
        call = next(c for c in connection.execute.await_args_list if "INSERT INTO labels" in c.args[0])
        context = json.loads(call.args[5])
        self.assertEqual(context["mail_profile"], profile())
        self.assertEqual(context["mail_profile_message_id"], decision.message_id)

    async def test_la_recherche_est_isolee_par_client_et_exclut_le_message_courant(self):
        connection = AsyncMock()
        connection.fetch.return_value = [{"label": "legitimate", "count": 2}]
        with patch("sentimail_v3.code.mail_profile.read_mail_profile", AsyncMock(return_value=profile())):
            memory = await profile_history(connection, "message-id", "client@example.org")
        self.assertEqual(memory["labels"], {"legitimate": 2})
        query, participant, _, message_id = connection.fetch.await_args.args
        self.assertIn("sentimail_same_client", query)
        self.assertIn("count(DISTINCT", query)
        self.assertEqual((participant, message_id), ("client@example.org", "message-id"))
