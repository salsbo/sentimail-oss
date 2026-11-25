from __future__ import annotations

import unittest

from sentimail_v3.observation.dossier.hooks.authentication import AuthenticationHook
from sentimail_v3.observation.dossier.models import InvestigationContext
from sentimail_v3.observation.parser import parse_message


def _context(raw: bytes) -> InvestigationContext:
    return InvestigationContext(
        raw, parse_message(raw), "sender@example.org", ["me@mondomaine.example"]
    )


def _message(authentication: str, from_header: str) -> bytes:
    return (
        f"Authentication-Results: {authentication}\r\n"
        f"From: {from_header}\r\n"
        "To: Me <me@mondomaine.example>\r\n"
        "Date: Tue, 11 Aug 2026 10:00:00 +0000\r\n"
        "Message-ID: <one@example.org>\r\n"
        "\r\n"
        "corps\r\n"
    ).encode()


async def _codes(raw: bytes) -> dict[str, str]:
    clues, _ = await AuthenticationHook().observe(_context(raw))
    return {clue.clue_code: clue.direction for clue in clues}


class DkimAlignmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_une_signature_du_domaine_affiche_reste_favorable(self) -> None:
        codes = await _codes(
            _message(
                "rspamd.sentimail; dkim=pass header.d=example.org; spf=pass",
                "Alice <alice@example.org>",
            )
        )
        self.assertEqual(codes.get("AUTH_DKIM_PASS"), "favorable")
        self.assertNotIn("AUTH_DKIM_UNALIGNED", codes)

    async def test_une_signature_d_un_autre_domaine_ne_rassure_pas(self) -> None:
        """Une plateforme d'envoi signe pour elle-même, pas pour l'expéditeur."""
        codes = await _codes(
            _message(
                "rspamd.sentimail; dkim=pass header.d=sendgrid.net; spf=none",
                "Ma Banque <service@mabanque.fr>",
            )
        )
        self.assertEqual(codes.get("AUTH_DKIM_UNALIGNED"), "adverse")
        self.assertNotIn("AUTH_DKIM_PASS", codes)

    async def test_un_dmarc_etabli_rend_l_alignement_dkim_sans_objet(self) -> None:
        """DMARC=pass prouve déjà l'alignement, par SPF ou par DKIM.

        Les lettres d'information passent par un prestataire qui signe de son
        propre domaine tout en gardant un SPF aligné : leur DKIM non aligné est
        le fonctionnement normal, pas un indice défavorable.
        """
        codes = await _codes(
            _message(
                "rspamd.sentimail; dmarc=pass; dkim=pass header.d=esp-mailer.net; spf=pass",
                "Boutique <info@boutique.fr>",
            )
        )
        self.assertNotIn("AUTH_DKIM_UNALIGNED", codes)
        self.assertEqual(codes.get("AUTH_DMARC_PASS"), "favorable")

    async def test_un_sous_domaine_signataire_reste_aligne(self) -> None:
        # Les grands émetteurs signent depuis un sous-domaine : c'est le même
        # propriétaire, et le refuser produirait une alerte sur du courrier
        # parfaitement ordinaire.
        codes = await _codes(
            _message(
                "rspamd.sentimail; dkim=pass header.d=mail.example.org",
                "Alice <alice@example.org>",
            )
        )
        self.assertEqual(codes.get("AUTH_DKIM_PASS"), "favorable")

    async def test_une_signature_sans_domaine_declare_reste_prudente(self) -> None:
        # Sans header.d exploitable, on ne peut rien conclure de l'alignement :
        # l'indice ne doit ni rassurer ni accuser.
        codes = await _codes(
            _message("rspamd.sentimail; dkim=pass", "Alice <alice@example.org>")
        )
        self.assertEqual(codes.get("AUTH_DKIM_PASS"), "neutral")


if __name__ == "__main__":
    unittest.main()


class FaitsPourLAvisTests(unittest.IsolatedAsyncioTestCase):
    """L'avis doit pouvoir nommer le domaine qui a écrit et le nom affiché."""

    async def test_le_dmarc_pass_porte_le_domaine_et_le_nom_affiche(self) -> None:
        clues, _ = await AuthenticationHook().observe(
            _context(
                _message(
                    "rspamd.sentimail; dmarc=pass; dkim=pass header.d=e-ca-paris.fr; spf=pass",
                    "Crédit Agricole d'Ile-de-France <diffusion@e-ca-paris.fr>",
                )
            )
        )
        dmarc = next(clue for clue in clues if clue.clue_code == "AUTH_DMARC_PASS")
        self.assertEqual(dmarc.facts.get("from_apex"), "e-ca-paris.fr")
        self.assertEqual(
            dmarc.facts.get("claimed_organisation"), "Crédit Agricole d'Ile-de-France"
        )

    async def test_le_dkim_pass_porte_le_domaine_signataire_meme_aligne_avec_dmarc(
        self,
    ) -> None:
        clues, _ = await AuthenticationHook().observe(
            _context(
                _message(
                    "rspamd.sentimail; dmarc=pass; dkim=pass header.d=e-ca-paris.fr; spf=pass",
                    "Crédit Agricole d'Ile-de-France <diffusion@e-ca-paris.fr>",
                )
            )
        )
        dkim = next(clue for clue in clues if clue.clue_code == "AUTH_DKIM_PASS")
        self.assertEqual(dkim.direction, "favorable")
        self.assertEqual(dkim.facts.get("signing_domain"), "e-ca-paris.fr")

    async def test_le_dkim_pass_porte_le_domaine_signataire_delegue_sous_dmarc(
        self,
    ) -> None:
        clues, _ = await AuthenticationHook().observe(
            _context(
                _message(
                    "rspamd.sentimail; dmarc=pass; dkim=pass header.d=esp-mailer.net; spf=pass",
                    "Boutique <info@boutique.fr>",
                )
            )
        )
        dkim = next(clue for clue in clues if clue.clue_code == "AUTH_DKIM_PASS")
        self.assertEqual(dkim.direction, "favorable")
        self.assertEqual(dkim.facts.get("signing_domain"), "esp-mailer.net")
