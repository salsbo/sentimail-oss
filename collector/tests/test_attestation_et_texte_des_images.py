"""Faux reçu Amazon du 3 novembre 2026 (M-fc7f44), livré légitime à 0,95.

Le message tenait dans une image : un reçu de 400 $ de cartes Google Play et
un numéro à rappeler, envoyé d'une adresse outlook.com jamais vue. Trois
contrôles se sont tus :

- l'usurpation d'Amazon, établie par sender_relation, a été mise sans charge
  parce que « outlook.com » avait déjà été livré une fois ; cette unique
  livraison (20 août) était un hameçonnage que le mainteneur avait étiqueté spam ;
- le contrôle de contenu ne lisait que le corps visible (12 caractères) et
  jamais le texte que l'OCR avait tiré de l'image ;
- requested_action a répondu read_only. Au rejeu, le même modèle répond
  phone_callback 11 fois sur 12 : l'erreur est un tirage, et le faisceau du
  faux reçu à l'enseigne d'une marque ne dépend plus de cette réponse.
"""

from __future__ import annotations

import os
import unittest
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import asyncpg

from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.tenancy import forget_cache
from sentimail_v3.observation.attachment_text import attachment_text_signals
from sentimail_v3.observation.deep_analysis import (
    _history,
    _sans_charge_si_cite,
    attested_locally,
)
from sentimail_v3.observation import deep_analysis
from sentimail_v3.observation.deep_hooks import SenderRelationHook, _cited_only_on_crowd_mailbox
from sentimail_v3.observation.storage import Store
from tests.test_favorable_evidence import _SMTP, _apex_email

_RECU_OCR = (
    "amazon. INVOICE\nORDER RECEIPT # 718-FUL-62233856\n"
    "Dear Valued Customer,\nYour requested delivery is currently being prepared "
    "by our team. The funds have been secured from your default payment source.\n"
    "If you need to make changes, manual phone verification is required.\n"
    "Google Play Gift Code 2 $400.00\nItems Subtotal $400.00\nGrand Total $400.00\n"
    "CUSTOMER SUPPORT AVAILABLE 24/7\nany adjustments to this finalized order "
    "must be processed manually over the\n+1 (813) 592-0404\nphone by a representative.\n"
)


def _image(text: str = _RECU_OCR) -> dict[str, object]:
    return {
        "path": "0.0.1",
        "filename": "image_20261030_031830.png",
        "content_type": "image/png",
        "sha256": "9427bf67f4da769ec6240de02233e36ef16a54b5d2c0bd3e7ca8c9a4c290b6e8",
        "extracted_text": text,
        "extracted_text_source": "ocr",
    }


class AttestationParAdresseTests(unittest.TestCase):
    """Une messagerie publique n'est pas un expéditeur."""

    def test_une_messagerie_publique_ne_s_atteste_pas_par_son_domaine(self) -> None:
        history = {
            "sender_apex": "outlook.com",
            "apex_delivered_count": 5,
            "sender_delivered_count": 0,
        }
        self.assertFalse(attested_locally(history, authenticated=True))

    def test_une_adresse_publique_deja_livree_s_atteste(self) -> None:
        # Un proche qui transfère un courrier Air France depuis sa boîte mac.com.
        history = {
            "sender_apex": "mac.com",
            "apex_delivered_count": 5,
            "sender_delivered_count": 2,
        }
        self.assertTrue(attested_locally(history, authenticated=True))

    def test_un_historique_sans_compte_par_adresse_n_atteste_pas(self) -> None:
        # Un historique conservé avant ce correctif n'a pas le compte par
        # adresse : il retombe du côté qui accuse, jamais sur l'apex.
        history = {"sender_apex": "gmail.com", "apex_delivered_count": 9}
        self.assertFalse(attested_locally(history, authenticated=True))

    def test_un_relais_de_confidentialite_reste_atteste_par_son_domaine(self) -> None:
        # Chaque adresse relais Apple naît d'une inscription à un seul service :
        # la première lettre de Termius n'est pas celle d'un inconnu.
        history = {
            "sender_apex": "appleid.com",
            "apex_delivered_count": 7,
            "sender_delivered_count": 0,
        }
        self.assertTrue(attested_locally(history, authenticated=True))

    def test_un_espace_partage_microsoft_s_atteste_par_adresse(self) -> None:
        history = {
            "sender_apex": "onmicrosoft.com",
            "apex_delivered_count": 4,
            "sender_delivered_count": 0,
        }
        self.assertFalse(attested_locally(history, authenticated=True))

    def test_un_domaine_propre_reste_atteste_par_son_domaine(self) -> None:
        # nintendo-europe.com, le cas qui a fait naître l'attestation.
        history = {
            "sender_apex": "nintendo-europe.com",
            "apex_delivered_count": 2,
            "sender_delivered_count": 0,
        }
        self.assertTrue(attested_locally(history, authenticated=True))

    def test_non_authentifie_n_atteste_jamais(self) -> None:
        history = {
            "sender_apex": "mac.com",
            "apex_delivered_count": 5,
            "sender_delivered_count": 5,
        }
        self.assertFalse(attested_locally(history, authenticated=False))


class TexteDesImagesTests(unittest.IsolatedAsyncioTestCase):
    """Le contrôle de contenu lit aussi ce que l'OCR a tiré des images."""

    async def test_le_recu_dans_l_image_est_un_contexte_financier(self) -> None:
        signals = await attachment_text_signals([_image()], visible_body_chars=12)
        codes = {str(signal["clue_code"]) for signal in signals}
        self.assertIn("CONTENT_FINANCIAL_CONTEXT", codes)
        financier = next(
            s for s in signals if s["clue_code"] == "CONTENT_FINANCIAL_CONTEXT"
        )
        self.assertEqual(financier["article_code"], "CONTENT-015")
        facts = financier["facts"]
        assert isinstance(facts, dict)
        self.assertEqual(facts["text_origin"], "attachment")
        self.assertEqual(facts["text_sources"], ["ocr"])
        self.assertTrue(facts["body_is_image"])
        self.assertIn("image", str(financier["statement"]))

    async def test_ne_crediter_jamais_sur_le_texte_d_une_image(self) -> None:
        # « Aucune pression repérée » et les crédits de code à usage unique ne
        # se lisent pas dans une image : l'attaquant y écrit ce qu'il veut.
        signals = await attachment_text_signals(
            [_image("Your verification code is 481920. It expires in 10 minutes.")],
            visible_body_chars=12,
        )
        self.assertFalse([s for s in signals if s["direction"] == "favorable"])
        codes = {str(s["clue_code"]) for s in signals}
        self.assertNotIn("CONTENT_NO_SENSITIVE_PRESSURE", codes)
        self.assertNotIn("CONTENT_ONE_TIME_CREDENTIAL_PROVIDED_NOT_REQUESTED", codes)

    async def test_un_indice_deja_lu_dans_le_corps_n_est_pas_redouble(self) -> None:
        signals = await attachment_text_signals(
            [_image()],
            visible_body_chars=400,
            already_observed={"CONTENT_FINANCIAL_CONTEXT"},
        )
        self.assertNotIn(
            "CONTENT_FINANCIAL_CONTEXT", {str(s["clue_code"]) for s in signals}
        )

    async def test_sans_texte_extrait_rien_n_est_constate(self) -> None:
        image = _image("")
        self.assertEqual(await attachment_text_signals([image], visible_body_chars=0), [])
        self.assertEqual(await attachment_text_signals([], visible_body_chars=0), [])

    async def test_un_corps_lisible_n_est_pas_dit_en_image(self) -> None:
        signals = await attachment_text_signals([_image()], visible_body_chars=900)
        financier = next(
            s for s in signals if s["clue_code"] == "CONTENT_FINANCIAL_CONTEXT"
        )
        facts = financier["facts"]
        assert isinstance(facts, dict)
        self.assertFalse(facts["body_is_image"])

    async def test_l_urgence_d_un_document_ne_charge_pas(self) -> None:
        # Des conditions générales en PDF parlent de délais sans rien presser.
        pdf = {
            "path": "0.1", "filename": "cgu.pdf", "content_type": "application/pdf",
            "sha256": "ab" * 32, "extracted_text_source": "pdf",
            "extracted_text": (
                "Urgent : vous devez accepter avant le 30 novembre, sous 48 heures, "
                "faute de quoi votre compte sera suspendu immédiatement. "
                "Le paiement de votre abonnement sera prélevé."
            ),
        }
        signals = await attachment_text_signals([pdf], visible_body_chars=900)
        codes = {str(s["clue_code"]) for s in signals}
        self.assertNotIn("CONTENT_URGENCY", codes)
        self.assertNotIn("CONTENT_SOCIAL_ENGINEERING_COMBINATION", codes)

    async def test_la_meme_urgence_dans_une_image_charge(self) -> None:
        image = _image(
            "Urgent : vous devez accepter avant le 30 novembre, sous 48 heures, "
            "faute de quoi votre compte sera suspendu immédiatement."
        )
        signals = await attachment_text_signals([image], visible_body_chars=12)
        self.assertIn("CONTENT_URGENCY", {str(s["clue_code"]) for s in signals})

    async def test_un_recu_en_pdf_reste_un_contexte_financier(self) -> None:
        pdf = {**_image(), "content_type": "application/pdf", "extracted_text_source": "pdf",
               "filename": "invoice.pdf"}
        signals = await attachment_text_signals([pdf], visible_body_chars=900)
        financier = next(s for s in signals if s["clue_code"] == "CONTENT_FINANCIAL_CONTEXT")
        self.assertIn("pièce jointe", str(financier["statement"]))

    async def test_le_faux_recu_a_l_enseigne_d_amazon_converge(self) -> None:
        # Une fois l'usurpation chargée et le reçu lu, le faisceau du faux
        # reçu à l'enseigne d'une marque (CORR-017) se forme.
        signals = await attachment_text_signals([_image()], visible_body_chars=12)
        observed = {str(s["clue_code"]) for s in signals} | {
            "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "HISTORY_FIRST_OBSERVATION",
        }
        codes = {clue["clue_code"] for clue in correlations(observed)}
        self.assertIn("CORRELATION_BRAND_TRANSACTION_LURE", codes)


_TRANSFERT = (
    "Regarde, c'est pour demain.\n\n---------- Forwarded message ---------\n"
    "De : La Poste <noreply@notif-laposte.info>\nObjet : Votre colis arrive !\n\n"
    "Bonjour, votre colis La Poste arrive demain entre 9 h et 13 h."
)


class MarqueSeulementCiteeTests(unittest.TestCase):
    """Un proche qui transfère un courrier de marque ne l'usurpe pas."""

    def test_un_transfert_depuis_gmail_ne_revendique_pas_la_marque_citee(self) -> None:
        self.assertTrue(
            _cited_only_on_crowd_mailbox(
                "La Poste", apex="gmail.com", display_name="Marie Durand",
                subject="Fwd: Votre colis arrive !", body=_TRANSFERT,
            )
        )

    def test_la_marque_citee_reste_ecrite_sans_charge(self) -> None:
        # Le texte « cité » est écrit par l'expéditeur : un faux transfert ne
        # doit pas faire disparaître la marque du dossier, seulement sa charge.
        clue = {
            "article_code": "DEEP-022",
            "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "direction": "adverse",
            "strength": 45,
            "statement": "Le message se présente au nom de La Poste.",
            "facts": {"from_apex": "gmail.com"},
        }
        neutre = _sans_charge_si_cite(clue)
        self.assertEqual(neutre["clue_code"], "IDENTITY_CLAIMED_ORGANISATION_REFUTED")
        self.assertEqual(neutre["direction"], "neutral")
        self.assertEqual(neutre["strength"], 0)
        self.assertEqual(neutre["facts"]["uncharged"], "cited_only")
        self.assertIn("La Poste", str(neutre["statement"]))

    def test_un_domaine_propre_repond_de_ce_qu_il_transfere(self) -> None:
        # Un fil cité peut être fabriqué : hors messagerie publique, rien ne change.
        self.assertFalse(
            _cited_only_on_crowd_mailbox(
                "La Poste", apex="colis-suivi.example", display_name="Service",
                subject="Fwd: Votre colis arrive !", body=_TRANSFERT,
            )
        )

    def test_la_marque_ecrite_hors_de_la_citation_reste_revendiquee(self) -> None:
        corps = "Votre colis La Poste est bloqué, payez 1,99 €.\n\n" + _TRANSFERT
        self.assertFalse(
            _cited_only_on_crowd_mailbox(
                "La Poste", apex="gmail.com", display_name="Marie Durand",
                subject="Votre colis", body=corps,
            )
        )

    def test_le_faux_recu_sans_citation_reste_revendique(self) -> None:
        corps = "[SnY-1592]\n\n" + _RECU_OCR
        self.assertFalse(
            _cited_only_on_crowd_mailbox(
                "Amazon", apex="outlook.com", display_name="Fabio Sanders",
                subject="Amartin, carrier picked up your order | FUL-62233856",
                body=corps,
            )
        )

    def test_un_objet_sans_prefixe_de_transfert_compte(self) -> None:
        self.assertFalse(
            _cited_only_on_crowd_mailbox(
                "La Poste", apex="gmail.com", display_name="Marie Durand",
                subject="La Poste : votre colis", body=_TRANSFERT,
            )
        )


class EnqueteurSurUnTransfertTests(unittest.IsolatedAsyncioTestCase):
    async def _observe(self, apex: str) -> tuple[list[dict[str, object]], dict[str, object]]:
        async def _claimed(*_: Any, **__: Any):
            return "La Poste", {"read": "la poste", "asked": True}

        async def _relation(*_: Any, **__: Any):
            return {
                "article_code": "DEEP-022",
                "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
                "direction": "adverse",
                "strength": 45,
                "confidence": 0.75,
                "statement": "Le message se présente au nom de La Poste.",
                "facts": {"from_apex": apex},
            }, {"searched": True}

        contexte = SimpleNamespace(
            pool=None, client=None, settings=None, clue_codes=set(),
            sender_apex=apex, display_name="Marie Durand",
            subject="Fwd: Votre colis arrive !", body=_TRANSFERT,
            from_address=f"marie.durand@{apex}", from_domain=apex,
            recipient="amartin@example.org", organisations={},
            sender_attested=False, sender_site=None, message_purpose="",
        )
        with patch.object(deep_analysis, "_claimed_organisation", _claimed), patch.object(
            deep_analysis, "_identity_relation", _relation
        ):
            return await SenderRelationHook().observe(contexte)  # type: ignore[arg-type]

    async def test_un_transfert_gmail_garde_le_constat_sans_charge(self) -> None:
        clues, facts = await self._observe("gmail.com")
        self.assertEqual(facts["claim_scope"], "quoted_only_on_crowd_mailbox")
        self.assertEqual(facts["claimed_organisation"], "La Poste")
        self.assertEqual(clues[0]["clue_code"], "IDENTITY_CLAIMED_ORGANISATION_REFUTED")
        self.assertEqual(clues[0]["direction"], "neutral")
        self.assertEqual(clues[0]["facts"]["uncharged"], "cited_only")

    async def test_le_meme_transfert_d_un_domaine_propre_reste_accuse(self) -> None:
        clues, facts = await self._observe("colis-suivi.example")
        self.assertNotIn("claim_scope", facts)
        self.assertEqual(clues[0]["direction"], "adverse")


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class HistoriqueSansSpamEtiqueteIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """La SQL de l'historique exécutée pour de vrai."""

    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.suffix = uuid.uuid4().hex
        self.recipient = f"attestation-{self.suffix}@example.org"
        self.created_messages: list[str] = []
        self.created_labels: list[int] = []
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
                "DELETE FROM labels WHERE id=ANY($1::bigint[])", self.created_labels
            )
            await self.pool.execute(
                "DELETE FROM messages WHERE id=ANY($1::uuid[])", self.created_messages
            )
        finally:
            await self.pool.close()

    async def _livre(self, sender: str, ordinal: int) -> str:
        store = Store(self.pool)
        result = await store.capture(
            _apex_email(sender, self.recipient, ordinal), sender, [self.recipient], _SMTP
        )
        self.created_messages.append(result.message_id)
        await store.mark_delivered(result.message_id)
        return result.message_id

    async def _courant(self, sender: str, ordinal: int) -> str:
        store = Store(self.pool)
        result = await store.capture(
            _apex_email(sender, self.recipient, ordinal), sender, [self.recipient], _SMTP
        )
        self.created_messages.append(result.message_id)
        return result.message_id

    async def _etiquette_spam(self, message_id: str, sender: str) -> None:
        label_id = await self.pool.fetchval(
            """
            INSERT INTO labels (
                message_id, source, label, is_ground_truth, active,
                sender_normalized, participant_email
            ) VALUES ($1::uuid, 'user', 'spam', true, true, $2, $3) RETURNING id
            """,
            message_id,
            sender,
            self.recipient,
        )
        self.created_labels.append(label_id)

    async def test_un_envoi_etiquete_spam_n_atteste_plus_son_domaine(self) -> None:
        apex = f"atteste-{self.suffix}.com"
        ancien = f"ancien@{apex}"
        message_id = await self._livre(ancien, 1)
        await self._etiquette_spam(message_id, ancien)
        current = await self._courant(f"nouveau@{apex}", 2)
        history = await _history(self.pool, current)
        self.assertEqual(history["apex_delivered_count"], 0)
        self.assertFalse(attested_locally(history, authenticated=True))

    async def test_un_envoi_livre_sans_etiquette_atteste_toujours(self) -> None:
        apex = f"atteste-{self.suffix}.com"
        await self._livre(f"ancien@{apex}", 1)
        current = await self._courant(f"nouveau@{apex}", 2)
        history = await _history(self.pool, current)
        self.assertEqual(history["apex_delivered_count"], 1)
        self.assertTrue(attested_locally(history, authenticated=True))

    async def test_une_adresse_outlook_neuve_n_herite_pas_d_une_autre(self) -> None:
        await self._livre(f"autre-{self.suffix}@outlook.com", 1)
        current = await self._courant(f"neuve-{self.suffix}@outlook.com", 2)
        history = await _history(self.pool, current)
        self.assertGreaterEqual(history["apex_delivered_count"], 1)
        self.assertEqual(history["sender_delivered_count"], 0)
        self.assertFalse(history["apex_established_locally"])
        self.assertFalse(attested_locally(history, authenticated=True))

    async def test_une_adresse_outlook_deja_livree_s_atteste(self) -> None:
        sender = f"proche-{self.suffix}@outlook.com"
        await self._livre(sender, 1)
        current = await self._courant(sender, 2)
        history = await _history(self.pool, current)
        self.assertEqual(history["sender_delivered_count"], 1)
        self.assertTrue(attested_locally(history, authenticated=True))

    async def test_un_joker_dans_l_adresse_n_herite_pas_d_une_voisine(self) -> None:
        # « _ » est un joker LIKE : jean_dupont héritait de jean.dupont.
        await self._livre(f"jean.dupont{self.suffix}@outlook.com", 1)
        current = await self._courant(f"jean_dupont{self.suffix}@outlook.com", 2)
        history = await _history(self.pool, current)
        self.assertEqual(history["previous_message_count"], 0)
        self.assertEqual(history["sender_delivered_count"], 0)
        self.assertFalse(attested_locally(history, authenticated=True))

    async def test_une_adresse_dont_l_envoi_est_etiquete_spam_ne_s_atteste_pas(
        self,
    ) -> None:
        sender = f"proche-{self.suffix}@outlook.com"
        message_id = await self._livre(sender, 1)
        await self._etiquette_spam(message_id, sender)
        current = await self._courant(sender, 2)
        history = await _history(self.pool, current)
        self.assertEqual(history["sender_delivered_count"], 0)
        self.assertFalse(attested_locally(history, authenticated=True))


if __name__ == "__main__":
    unittest.main()
