"""Le destinataire choisit s'il reçoit un accusé après ses directives.

« Active l'accusé de réception » / « désactive l'accusé de réception » est un
réglage, pas une directive de livraison : il se lit sans modèle, s'applique
sans appel LLM, et se confirme toujours - c'est le changement d'état qui est
confirmé, pas la directive.
"""

from __future__ import annotations

import unittest

from sentimail_v3.conversation.receipt_preference import (
    get_receipt_enabled,
    parse_receipt_toggle,
    receipt_toggle_label,
    receipt_toggle_sentence,
    set_receipt_enabled,
)


class LectureDuReglageTests(unittest.TestCase):
    def test_desactiver_se_reconnait(self) -> None:
        for texte in (
            "Désactive l'accusé de réception",
            "desactive les accusés de réception s'il te plaît",
            "arrête les accusés de réception",
            "je ne veux plus d'accusé de réception",
        ):
            with self.subTest(texte=texte):
                self.assertIs(parse_receipt_toggle(texte), False)

    def test_activer_se_reconnait(self) -> None:
        for texte in (
            "Active l'accusé de réception",
            "réactive les accusés de réception",
            "remets l'accusé de réception",
        ):
            with self.subTest(texte=texte):
                self.assertIs(parse_receipt_toggle(texte), True)

    def test_le_reste_ne_bascule_rien(self) -> None:
        for texte in (
            "A",
            "Tu t'es trompée : c'est un message légitime, livre-le-moi.",
            "active la livraison",
            "j'ai bien reçu ton accusé de réception",
            "",
        ):
            with self.subTest(texte=texte):
                self.assertIsNone(parse_receipt_toggle(texte))


class PhraseCanoniqueDeLaBasculeTests(unittest.TestCase):
    """La phrase pré-remplie derrière le lien doit être reconnue sans modèle.

    Un lien qui bascule l'accusé pré-remplit une réponse : le corps généré
    doit décoder exactement comme si le destinataire l'avait tapé lui-même.
    """

    def test_le_libelle_activé_propose_de_désactiver(self) -> None:
        self.assertEqual(
            receipt_toggle_label(True), "désactive l'accusé de réception"
        )

    def test_le_libelle_desactive_propose_d_activer(self) -> None:
        self.assertEqual(
            receipt_toggle_label(False), "active l'accusé de réception"
        )

    def test_aller_retour_depuis_active_desactive(self) -> None:
        phrase = receipt_toggle_sentence(True)
        self.assertIs(parse_receipt_toggle(phrase), False)

    def test_aller_retour_depuis_desactive_active(self) -> None:
        phrase = receipt_toggle_sentence(False)
        self.assertIs(parse_receipt_toggle(phrase), True)


class StockageTests(unittest.IsolatedAsyncioTestCase):
    def _pool(self, valeur):
        appels = []

        class _Pool:
            async def fetchval(self, query, *args):
                appels.append(("fetchval", query, args))
                return valeur

            async def execute(self, query, *args):
                appels.append(("execute", query, args))

        return _Pool(), appels

    async def test_active_par_defaut(self) -> None:
        pool, _ = self._pool(None)
        self.assertTrue(await get_receipt_enabled(pool, "operateur@mondomaine.example"))

    async def test_un_reglage_desactive_se_lit(self) -> None:
        pool, _ = self._pool(False)
        self.assertFalse(await get_receipt_enabled(pool, "operateur@mondomaine.example"))

    async def test_l_ecriture_conserve_le_participant_et_l_etat(self) -> None:
        pool, appels = self._pool(None)
        await set_receipt_enabled(pool, "operateur@mondomaine.example", False)
        self.assertEqual(len(appels), 1)
        _, query, args = appels[0]
        self.assertIn("participant_preferences", query)
        self.assertIn("operateur@mondomaine.example", args)


if __name__ == "__main__":
    unittest.main()
