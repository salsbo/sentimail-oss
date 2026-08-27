"""Chantier « indices favorables » (22/08) : quatre critères génériques.

Un dossier légitime en premier contact ne portait souvent aucune preuve à
décharge - seulement l'absence de charge, ce qui ne distingue rien et finit en
ask_user. Chaque indice ici réunit plusieurs conditions distinctes : aucune,
prise seule, ne doit déclencher le fait favorable (anti-contrefaçon).
"""

from __future__ import annotations

import inspect
import os
import re
import unittest
from pathlib import Path

import asyncpg

from sentimail_v3.code.tenancy import forget_cache
from sentimail_v3.observation.deep_analysis import _SIGNAL_RULES, _history, _signals
from sentimail_v3.observation.dossier.hooks.headers import HeadersHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message
from sentimail_v3.observation.storage import Store


def _context(raw: bytes, recipients: list[str]) -> InvestigationContext:
    return InvestigationContext(raw, parse_message(raw), "sender@example.org", recipients)


def _message(headers: str, body: str = "corps ordinaire") -> bytes:
    return (
        "From: Expediteur <sender@example.org>\r\n"
        f"{headers}"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        "Message-ID: <one@example.org>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"{body}\r\n"
    ).encode()


async def _header_codes(raw: bytes, recipients: list[str]) -> dict[str, str]:
    clues, _ = await HeadersHook().observe(_context(raw, recipients))
    return {clue.clue_code: clue.direction for clue in clues}


def _codes(signals: list[dict[str, object]]) -> set[str]:
    return {str(value.get("article_code")) for value in signals}


class Rfc8058UnsubscribeTests(unittest.IsolatedAsyncioTestCase):
    """Indice n°3 : le hook headers ne constate qu'une STRUCTURE neutre.

    Round 1 de revue (24/08) : le hook n'a pas accès à l'authentification, il
    ne peut donc jamais rendre ce fait favorable seul - un From usurpé aligne
    ses en-têtes tout aussi facilement. Voir CorrelationRfc8058AuthentifieTests
    pour la preuve favorable réelle, qui exige en plus `authenticated`.
    """

    async def test_desinscription_alignee_et_one_click_est_constatee_neutre(
        self,
    ) -> None:
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\n"
            "List-Unsubscribe: <https://example.org/unsub?id=42>\r\n"
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertEqual(codes.get("HEADERS_RFC8058_STRUCTURE"), "neutral")
        self.assertNotIn("favorable", codes.values())

    async def test_cas_limite_apex_non_aligne_ne_declenche_rien(self) -> None:
        """Un compte ESP jetable pointe son désabonnement ailleurs : condition dure."""
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\n"
            "List-Unsubscribe: <https://tracking.autre-domaine.net/unsub?id=42>\r\n"
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RFC8058_STRUCTURE", codes)

    async def test_cas_limite_sans_en_tete_one_click_ne_declenche_rien(self) -> None:
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\n"
            "List-Unsubscribe: <https://example.org/unsub?id=42>\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RFC8058_STRUCTURE", codes)

    async def test_cas_limite_lien_mailto_seul_ne_declenche_rien(self) -> None:
        raw = _message(
            "To: Moi <me@mondomaine.example>\r\n"
            "List-Unsubscribe: <mailto:unsub@example.org>\r\n"
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
        )
        codes = await _header_codes(raw, ["me@mondomaine.example"])
        self.assertNotIn("HEADERS_RFC8058_STRUCTURE", codes)


class CorrelationRfc8058AuthentifieTests(unittest.TestCase):
    """Indice n°3, preuve favorable réelle : CORR-013 exige l'authentification.

    Régression du round 1 : un From usurpé et NON authentifié, même avec des
    en-têtes RFC 8058 syntaxiquement alignés, ne doit produire AUCUNE preuve
    favorable.
    """

    def test_alignement_et_authentification_ensemble_declenchent_corr_013(
        self,
    ) -> None:
        signals = _signals(
            [],
            [],
            {},
            True,
            authenticated=True,
            headers_facts={
                "rfc8058_structure_aligned": True,
                "unsubscribe_apex": "example.org",
            },
        )
        self.assertIn("CORR-013", _codes(signals))

    def test_regression_from_usurpe_non_authentifie_ne_produit_rien(self) -> None:
        """CRITIQUE round 1 : alignement syntaxique seul, sans authentification
        réelle, ne doit jamais valoir une preuve favorable - c'est exactement
        ce qu'un From usurpé peut fabriquer sans rien contrôler."""
        signals = _signals(
            [],
            [],
            {},
            True,
            authenticated=False,
            headers_facts={
                "rfc8058_structure_aligned": True,
                "unsubscribe_apex": "example.org",
            },
        )
        self.assertNotIn("CORR-013", _codes(signals))
        self.assertEqual(
            [s for s in signals if s.get("direction") == "favorable"], []
        )

    def test_cas_limite_authentifie_sans_structure_alignee_ne_declenche_rien(
        self,
    ) -> None:
        signals = _signals(
            [],
            [],
            {},
            True,
            authenticated=True,
            headers_facts={"rfc8058_structure_aligned": False},
        )
        self.assertNotIn("CORR-013", _codes(signals))

    def test_sans_faits_headers_ne_declenche_rien(self) -> None:
        signals = _signals([], [], {}, True, authenticated=True, headers_facts=None)
        self.assertNotIn("CORR-013", _codes(signals))


class CoherenceTransactionnelleTests(unittest.TestCase):
    """Indice n°1 : corrélation transactionnelle. Les trois faits ensemble."""

    def test_les_trois_faits_reunis_declenchent_le_signal(self) -> None:
        signals = _signals(
            [],
            [],
            {"sender_domain_age_days": 800},
            True,
            authenticated=True,
            content_context={"purpose": "one_time_authentication"},
        )
        self.assertIn("CORR-012", _codes(signals))

    def test_cas_limite_non_authentifie_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {"sender_domain_age_days": 800},
            True,
            authenticated=False,
            content_context={"purpose": "one_time_authentication"},
        )
        self.assertNotIn("CORR-012", _codes(signals))

    def test_cas_limite_domaine_jeune_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {"sender_domain_age_days": 10},
            True,
            authenticated=True,
            content_context={"purpose": "one_time_authentication"},
        )
        self.assertNotIn("CORR-012", _codes(signals))

    def test_cas_limite_nature_non_transactionnelle_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {"sender_domain_age_days": 800},
            True,
            authenticated=True,
            content_context={"purpose": "unknown"},
        )
        self.assertNotIn("CORR-012", _codes(signals))


class ApexEprouveLocalementTests(unittest.TestCase):
    """Indice n°2 : apex éprouvé localement pour une adresse jamais vue."""

    def test_apex_etabli_sur_premier_message_de_l_adresse_declenche_le_signal(
        self,
    ) -> None:
        signals = _signals(
            [],
            [],
            {"previous_message_count": 0, "apex_established_locally": True},
            True,
        )
        self.assertIn("HIST-004", _codes(signals))

    def test_cas_limite_apex_non_etabli_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {"previous_message_count": 0, "apex_established_locally": False},
            True,
        )
        self.assertNotIn("HIST-004", _codes(signals))

    def test_cas_limite_adresse_deja_vue_ne_declenche_rien(self) -> None:
        """Même un apex éprouvé ne parle plus une fois l'adresse elle-même connue :
        c'est alors HIST-001/HIST-003 qui la jugent, pas ce fait de première fois."""
        signals = _signals(
            [],
            [],
            {"previous_message_count": 5, "apex_established_locally": True},
            True,
        )
        self.assertNotIn("HIST-004", _codes(signals))


class LangueHabituelleTests(unittest.TestCase):
    """Indice n°4 : langue habituelle du destinataire, faible et prudent."""

    def test_langue_dominante_et_forte_dominance_declenche_le_signal(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "recipient_dominant_language": "fr",
                "recipient_language_total": 12,
                "recipient_language_dominance": 0.8,
            },
            True,
            nature={"language": "fr"},
        )
        self.assertIn("HIST-005", _codes(signals))

    def test_cas_limite_langue_minoritaire_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "recipient_dominant_language": "fr",
                "recipient_language_total": 12,
                "recipient_language_dominance": 0.5,
            },
            True,
            nature={"language": "fr"},
        )
        self.assertNotIn("HIST-005", _codes(signals))

    def test_cas_limite_historique_trop_court_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "recipient_dominant_language": "fr",
                "recipient_language_total": 5,
                "recipient_language_dominance": 1.0,
            },
            True,
            nature={"language": "fr"},
        )
        self.assertNotIn("HIST-005", _codes(signals))

    def test_cas_limite_langue_courante_differente_ne_declenche_rien(self) -> None:
        signals = _signals(
            [],
            [],
            {
                "recipient_dominant_language": "fr",
                "recipient_language_total": 12,
                "recipient_language_dominance": 0.9,
            },
            True,
            nature={"language": "en"},
        )
        self.assertNotIn("HIST-005", _codes(signals))


class NonCollisionTests(unittest.TestCase):
    """Un article_code réutilisé écraserait silencieusement une entrée existante."""

    def test_les_article_codes_de_la_table_de_signaux_sont_uniques(self) -> None:
        from sentimail_v3.observation import deep_analysis

        source = Path(inspect.getsourcefile(deep_analysis)).read_text(encoding="utf-8")
        match = re.search(
            r"_SIGNAL_RULES: dict\[str, tuple\[str, str, int, float, str\]\] = \{(.*?)\n\}\n",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "table _SIGNAL_RULES introuvable dans la source")
        keys = re.findall(r'^\s{4}"([A-Z]+-\d+)":\s*\(', match.group(1), re.MULTILINE)
        self.assertGreater(len(keys), 0)
        self.assertEqual(
            len(keys), len(set(keys)), "un article_code est défini plusieurs fois"
        )

    def test_les_nouveaux_codes_sont_bien_presents_une_seule_fois(self) -> None:
        for code in ("CORR-012", "HIST-004", "HIST-005", "CORR-013"):
            with self.subTest(code=code):
                self.assertIn(code, _SIGNAL_RULES)

    def test_le_code_headers_004_n_est_pas_dans_la_table_de_signaux(self) -> None:
        """HEADERS-004 est produit par le hook, pas par la table de signaux
        profonds : il ne doit donc pas y apparaître une seconde fois."""
        self.assertNotIn("HEADERS-004", _SIGNAL_RULES)


_SMTP = {
    "peer_ip": "172.20.0.8",
    "peer_port": 25,
    "helo": "mx.example",
    "protocol": "ESMTP",
    "tls": {},
    "authenticated": False,
    "mail_options": [],
    "rcpt_options": {},
}


def _french_email(sender: str, recipient: str, ordinal: int) -> bytes:
    return (
        f"From: Expediteur {ordinal} <{sender}>\r\n"
        f"To: Destinataire <{recipient}>\r\n"
        f"Subject: Confirmation numero {ordinal}\r\n"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        f"Message-ID: <langue-{ordinal}@example.org>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Bonjour, nous vous confirmons que votre commande a bien ete "
        "expediee et vous remercions de votre confiance en notre "
        f"service, reference {ordinal}.\r\n"
    ).encode()


def _apex_email(sender: str, recipient: str, ordinal: int) -> bytes:
    return (
        f"From: Expediteur {ordinal} <{sender}>\r\n"
        f"To: Destinataire <{recipient}>\r\n"
        f"Subject: Message {ordinal}\r\n"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        f"Message-ID: <apex-{ordinal}@example.org>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        f"Contenu ordinaire {ordinal}.\r\n"
    ).encode()


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class HistorySqlIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """La SQL des indices n°2 et n°4 exécutée pour de vrai, pas simulée."""

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, admin_email, verified_at)
            VALUES ('example.org','active','user@example.org',now())
            ON CONFLICT (fqdn) DO UPDATE SET status='active'
            """
        )
        forget_cache()

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def test_un_apex_eprouve_par_trois_autres_adresses_est_constate(
        self,
    ) -> None:
        store = Store(self.pool)
        recipient = "dest-apex-1@example.org"
        for ordinal in range(1, 4):
            sender = f"seniority-{ordinal}@apex-eprouve.example"
            result = await store.capture(
                _apex_email(sender, recipient, ordinal), sender, [recipient], _SMTP
            )
            await store.mark_delivered(result.message_id)
            # L'ancienneté de sept jours protège contre un domaine qui
            # s'auto-blanchirait en enchaînant des adresses fraîches.
            await self.pool.execute(
                "UPDATE messages SET captured_at=now() - interval '10 days' "
                "WHERE id=$1::uuid",
                result.message_id,
            )
        sender_nouveau = f"jamais-vue@apex-eprouve.example"
        current = await store.capture(
            _apex_email(sender_nouveau, recipient, 4), sender_nouveau, [recipient], _SMTP
        )
        history = await _history(self.pool, current.message_id)
        self.assertEqual(history["previous_message_count"], 0)
        self.assertEqual(history["apex_delivered_count"], 3)
        self.assertGreaterEqual(history["apex_track_record_age_days"], 7)
        self.assertTrue(history["apex_established_locally"])

    async def test_une_etiquette_defavorable_sur_l_apex_neutralise_le_fait(
        self,
    ) -> None:
        store = Store(self.pool)
        recipient = "dest-apex-2@example.org"
        first_message_id = None
        for ordinal in range(1, 4):
            sender = f"poison-{ordinal}@apex-etiquete.example"
            result = await store.capture(
                _apex_email(sender, recipient, ordinal), sender, [recipient], _SMTP
            )
            first_message_id = first_message_id or result.message_id
            await store.mark_delivered(result.message_id)
            await self.pool.execute(
                "UPDATE messages SET captured_at=now() - interval '10 days' "
                "WHERE id=$1::uuid",
                result.message_id,
            )
        # Une seule étiquette humaine défavorable, n'importe où sur l'apex,
        # neutralise le fait pour toutes les adresses de ce domaine.
        await self.pool.execute(
            """
            INSERT INTO labels (
                message_id, source, label, is_ground_truth, active,
                sender_normalized, participant_email
            ) VALUES ($1::uuid, 'user', 'spam', true, true, $2, $3)
            """,
            first_message_id,
            "poison-1@apex-etiquete.example",
            recipient,
        )
        sender_nouveau = "jamais-vue@apex-etiquete.example"
        current = await store.capture(
            _apex_email(sender_nouveau, recipient, 4), sender_nouveau, [recipient], _SMTP
        )
        history = await _history(self.pool, current.message_id)
        self.assertEqual(history["apex_adverse_label_count"], 1)
        self.assertFalse(history["apex_established_locally"])

    async def test_la_langue_dominante_du_destinataire_est_constatee(self) -> None:
        store = Store(self.pool)
        recipient = "polyglotte@example.org"
        for ordinal in range(1, 11):
            sender = f"expediteur-{ordinal}@divers-mail.example"
            result = await store.capture(
                _french_email(sender, recipient, ordinal), sender, [recipient], _SMTP
            )
            await store.mark_delivered(result.message_id)
        sender_courant = "expediteur-11@divers-mail.example"
        current = await store.capture(
            _french_email(sender_courant, recipient, 11), sender_courant, [recipient], _SMTP
        )
        history = await _history(self.pool, current.message_id)
        self.assertEqual(history["recipient_dominant_language"], "fr")
        self.assertGreaterEqual(history["recipient_language_total"], 10)
        self.assertGreaterEqual(history["recipient_language_dominance"], 0.7)


if __name__ == "__main__":
    unittest.main()
