"""Les questions qu'on n'aurait pas dû poser.

Du 27 août au 3 septembre 2026, la part des dossiers renvoyés à l'utilisateur
est passée de 6 % à 22 %. Deux mécanismes l'expliquaient, chacun tenu ici par
un test : une accusation d'identité portée sur la seule graphie contre un
expéditeur authentifié qui avait déjà écrit (Nintendo, Insta360, Sephora) ; et
un spam forgé que rien ne qualifiait de sollicitation (Herz P1 depuis wuv.de :
« one-time purchase » lu comme un code à usage unique, « Save 50% » sans
registre, envoi de masse en premier contact absent du profil de spam).
"""

from __future__ import annotations

import asyncio
import os
import unittest
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import asyncpg

from sentimail_v3.code.organisation_lookup import official_apexes
from sentimail_v3.judgment.verdict_engine import _material_spam_profile
from sentimail_v3.observation import deep_analysis
from sentimail_v3.observation.deep_analysis import _history, attested_locally
from sentimail_v3.observation.deep_hooks import SenderRelationHook
from sentimail_v3.observation.dossier.hooks.content import _message_purpose
from sentimail_v3.observation.dossier.hooks.nature import NatureHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message
from sentimail_v3.code.tenancy import forget_cache
from sentimail_v3.observation.storage import Store
from tests.test_favorable_evidence import _SMTP, _apex_email


class FinaliteTests(unittest.TestCase):
    def test_un_achat_unique_n_est_pas_un_code_a_usage_unique(self) -> None:
        # « One-time purchase with a free companion app » : une réclame, pas
        # un lien de connexion. Lu comme tel, le message gagnait un indice
        # favorable et échappait au contrôle de cohérence d'activité.
        self.assertEqual(
            _message_purpose(
                "NO SUBSCRIPTION One-time purchase with a free companion app "
                "and no monthly fee."
            ),
            "unknown",
        )

    def test_un_code_a_usage_unique_reste_reconnu(self) -> None:
        for phrase in (
            "Here is your one-time code: 123456",
            "Voici ton code à usage unique",
            "Use this one-time link to sign in",
        ):
            with self.subTest(phrase=phrase):
                self.assertEqual(_message_purpose(phrase), "one_time_authentication")


RECLAME_FORGEE = (
    b"From: Herz P1 Clinical Research <support@media-group.example>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: This Band Takes a Quieter More Focused Approach\r\n"
    b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
    b"<html><body><p>INDEPENDENT DEAL REPORT</p>"
    b"<p>A closer look at the Smart Band and its current 50% offer.</p>"
    b"<p>CURRENT DEAL: Save 50% while the promotion remains active.</p>"
    b"<p><a href='https://storage.example/ls'>CHECK CURRENT DEAL</a></p>"
    b"<p>Unsubscribe from future emails.</p></body></html>\r\n"
)
NEWSLETTER_DECLAREE = (
    b"From: Nintendo <nintendo@mail.nintendo-europe.example>\r\n"
    b"To: user@example.org\r\n"
    b"Subject: En cours | offre Blockbuster\r\n"
    b"List-Unsubscribe: <https://click.example/u/1>\r\n"
    b"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Jusqu'au 13/09, economisez jusqu'a 75 % sur de grandes aventures.\r\n"
    b"Offre speciale : promo sur une selection de jeux.\r\n"
)


def _nature(raw: bytes) -> tuple[list[Any], dict[str, object]]:
    context = InvestigationContext(
        raw=raw,
        parsed=parse_message(raw),
        envelope_from="bounce@sender.example",
        recipients=["user@example.org"],
    )
    return asyncio.run(NatureHook().observe(context))


class RegistreCommercialTests(unittest.TestCase):
    def test_une_reclame_sans_desinscription_est_une_sollicitation(self) -> None:
        clues, facts = _nature(RECLAME_FORGEE)
        codes = {clue.clue_code for clue in clues}
        self.assertIn("commercial", facts["claim_registers"])
        self.assertIn("NATURE_SOLICITATION_WITHOUT_OPT_OUT", codes)

    def test_une_newsletter_declaree_avec_remise_n_est_pas_blamee(self) -> None:
        clues, facts = _nature(NEWSLETTER_DECLAREE)
        codes = {clue.clue_code for clue in clues}
        self.assertIn("commercial", facts["claim_registers"])
        self.assertNotIn("NATURE_SOLICITATION_WITHOUT_OPT_OUT", codes)
        self.assertNotIn("NATURE_UNVERIFIABLE_PROMOTIONAL_CLAIMS", codes)

    def test_une_seule_mention_commerciale_ne_fait_pas_un_registre(self) -> None:
        raw = (
            b"From: Colleague <colleague@example.org>\r\n"
            b"To: user@example.org\r\n"
            b"Subject: Compte rendu\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Le fournisseur propose une offre speciale, je te transmets.\r\n"
        )
        _, facts = _nature(raw)
        self.assertNotIn("commercial", facts["claim_registers"])


class ProfilDeSpamTests(unittest.TestCase):
    def test_un_envoi_de_masse_forge_en_premier_contact_complete_le_profil(
        self,
    ) -> None:
        self.assertTrue(
            _material_spam_profile(
                {
                    "AUTH_DMARC_FAIL",
                    "HISTORY_FIRST_OBSERVATION",
                    "NATURE_UNSOLICITED_BULK_FIRST_CONTACT",
                }
            )
        )

    def test_la_forge_seule_ne_fait_pas_le_profil(self) -> None:
        self.assertFalse(
            _material_spam_profile({"AUTH_DMARC_FAIL", "HISTORY_FIRST_OBSERVATION"})
        )


def _resultats(*hotes: str) -> list[dict[str, object]]:
    return [{"title": hote, "url": f"https://{hote}/page", "content": ""} for hote in hotes]


class DomainesOfficielsTests(unittest.TestCase):
    def test_seuls_les_domaines_qui_portent_le_nom_sont_officiels(self) -> None:
        # La recherche sur « Nintendo » rendait gouv.fr et lechompenchaine.fr :
        # cités comme officiels, ils faisaient accuser nintendo-europe.com.
        self.assertEqual(
            official_apexes(
                _resultats("www.gouv.fr", "www.nintendo.com", "lechompenchaine.fr"),
                organisation="Nintendo",
            ),
            ["nintendo.com"],
        )

    def test_un_nom_compose_reconnait_ses_domaines(self) -> None:
        self.assertEqual(
            official_apexes(
                _resultats("www.credit-agricole.fr", "www.ca-paris.com", "wikipedia.org"),
                organisation="Crédit Agricole d'Ile-de-France",
            ),
            ["credit-agricole.fr"],
        )

    def test_sans_nom_la_liste_reste_entiere(self) -> None:
        self.assertEqual(
            official_apexes(_resultats("www.gouv.fr", "www.nintendo.com")),
            ["gouv.fr", "nintendo.com"],
        )


class AttestationLocaleTests(unittest.TestCase):
    def test_authentifie_et_deja_livre_atteste(self) -> None:
        self.assertTrue(attested_locally({"apex_delivered_count": 2}, authenticated=True))

    def test_jamais_livre_n_atteste_pas(self) -> None:
        self.assertFalse(attested_locally({"apex_delivered_count": 0}, authenticated=True))

    def test_non_authentifie_n_atteste_pas(self) -> None:
        self.assertFalse(attested_locally({"apex_delivered_count": 5}, authenticated=False))


class _Settings:
    search_api_key = "cle"
    search_base_url = "https://api.exemple.test"


class AccusationSurLaGraphieTests(unittest.IsolatedAsyncioTestCase):
    async def _relation(self, *, attested: bool) -> dict[str, object] | None:
        async def _about_name(*_: Any, **__: Any):
            return [{"title": "Nintendo", "url": "https://www.nintendo.com/"}], [
                "nintendo.com"
            ]

        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch(
            "sentimail_v3.observation.organisation_search.about_name", _about_name
        ):
            clue, _ = await deep_analysis._identity_relation(
                None,
                None,
                _Settings(),
                display_name="Nintendo",
                from_apex="nintendo-europe.com",
                attested_locally=attested,
            )
        return clue

    async def test_un_expediteur_authentifie_deja_livre_est_constate_sans_charge(
        self,
    ) -> None:
        # nintendo-europe.com, DMARC aligné, livré deux fois les 20 et 22 août,
        # accusé à 65 le 3 septembre parce qu'il « ajoute un mot » à
        # nintendo.com. Le constat reste écrit et appris ; il ne charge plus.
        clue = await self._relation(attested=True)
        self.assertIsNotNone(clue)
        assert clue is not None
        self.assertEqual(clue["article_code"], "DEEP-022")
        self.assertEqual(clue["direction"], "neutral")
        self.assertEqual(clue["strength"], 0)
        self.assertTrue(clue["facts"]["attested_locally"])

    async def test_un_inconnu_qui_accole_la_marque_reste_accuse(self) -> None:
        clue = await self._relation(attested=False)
        assert clue is not None
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["strength"], 65)


class LeHookPorteLAttestationTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_hook_transmet_l_attestation_locale(self) -> None:
        recu: dict[str, object] = {}

        async def _relation(*_: Any, **kwargs: Any):
            recu.update(kwargs)
            return None, {"searched": True}

        contexte = SimpleNamespace(
            pool=None,
            client=None,
            settings=_Settings(),
            clue_codes=set(),
            sender_apex="nintendo-europe.com",
            display_name="Nintendo",
            organisations={},
            sender_attested=True,
        )
        with patch.object(deep_analysis, "_identity_relation", _relation):
            await SenderRelationHook().observe(contexte)  # type: ignore[arg-type]
        self.assertTrue(recu.get("attested_locally"))


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class ApexDejaLivreIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Le compte des livraisons de l'apex se lit aussi pour une adresse connue."""

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.created_messages: list[str] = []
        self.sender = f"nintendo@mail.apex-connu-{uuid.uuid4().hex}.com"  # audit-ok: domaine aléatoire créé pour l'essai
        await self.pool.execute(
            """
            INSERT INTO domains (fqdn, status, admin_email, verified_at)
            VALUES ('example.org','active','user@example.org',now())
            ON CONFLICT (fqdn) DO UPDATE SET status='active'
            """
        )
        forget_cache()

    async def asyncTearDown(self) -> None:
        try:
            await self.pool.execute(
                "DELETE FROM messages WHERE id=ANY($1::uuid[])", self.created_messages
            )
        finally:
            await self.pool.close()

    async def test_une_adresse_connue_garde_le_compte_de_son_apex(self) -> None:
        store = Store(self.pool)
        recipient = "dest-apex-connu@example.org"
        # .example n'est pas un suffixe PSL : tous ses sous-domaines devenaient
        # le même apex « example » et additionnaient les fixtures voisines.
        sender = self.sender
        for ordinal in range(1, 3):
            result = await store.capture(
                _apex_email(sender, recipient, ordinal), sender, [recipient], _SMTP
            )
            self.created_messages.append(result.message_id)
            await store.mark_delivered(result.message_id)
        current = await store.capture(
            _apex_email(sender, recipient, 3), sender, [recipient], _SMTP
        )
        self.created_messages.append(current.message_id)
        history = await _history(self.pool, current.message_id)
        self.assertEqual(history["previous_message_count"], 2)
        self.assertEqual(history["apex_delivered_count"], 2)
        self.assertFalse(history["apex_established_locally"])
