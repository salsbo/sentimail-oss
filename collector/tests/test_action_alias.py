from __future__ import annotations

import unittest

from sentimail_v3.conversation.conversation import ConversationStore


class AliasTests(unittest.IsolatedAsyncioTestCase):
    """L'adresse affichée doit être une adresse qui reçoit.

    MAIA signait « maia@sentimail.example » mais n'écoutait que sur
    « maia@sentinel.sentimail.example ». Écrire spontanément à l'expéditeur affiché
    rebondissait en « User doesn't exist » : le système tendait un piège à la
    personne qu'il protège.
    """

    def _store(self, aliases: tuple[str, ...]) -> ConversationStore:
        # Sans `settings` : _identity() retombe sur les valeurs figées ici,
        # sans jamais toucher `pool` (laissé à None à dessein).
        return ConversationStore(
            pool=None,
            action_address="maia@sentinel.mondomaine.example",
            assistant_sender="MAIA - SentiMail <maia@mondomaine.example>",
            render_sandbox_url="",
            action_aliases=aliases,
            encryption_key=None,
        )

    async def test_l_adresse_affichee_est_une_adresse_d_action(self) -> None:
        store = self._store(("maia@mondomaine.example",))
        self.assertTrue(await store.is_action_recipient(["maia@mondomaine.example"]))

    async def test_l_adresse_historique_continue_de_fonctionner(self) -> None:
        store = self._store(("maia@mondomaine.example",))
        self.assertTrue(await store.is_action_recipient(["maia@sentinel.mondomaine.example"]))

    async def test_la_casse_et_le_nom_affiche_ne_genent_pas(self) -> None:
        store = self._store(("maia@mondomaine.example",))
        self.assertTrue(
            await store.is_action_recipient(["MAIA - SentiMail <MAIA@Mondomaine.EXAMPLE>"])
        )

    async def test_une_adresse_etrangere_n_est_pas_une_adresse_d_action(self) -> None:
        store = self._store(("maia@mondomaine.example",))
        self.assertFalse(await store.is_action_recipient(["operateur@mondomaine.example"]))
        self.assertFalse(await store.is_action_recipient(["maia@autre-domaine.fr"]))


class ConfigurationTests(unittest.TestCase):
    def test_la_configuration_declare_l_alias(self) -> None:
        """Un alias absent du déploiement ne protège rien."""
        import pathlib
        import re

        compose = (
            pathlib.Path(__file__).resolve().parents[2] / "docker-compose.yml"
        ).read_text("utf-8")
        expediteurs = set(re.findall(r'ASSISTANT_SENDER:\s*"[^<]*<([^>]+)>"', compose))
        alias = set()
        for ligne in re.findall(r'ACTION_ALIASES:\s*"([^"]+)"', compose):
            alias.update(v.strip().casefold() for v in ligne.split(","))
        adresses = set(re.findall(r'ACTION_ADDRESS:\s*"([^"]+)"', compose))
        manquants = {e.casefold() for e in expediteurs} - alias - {
            a.casefold() for a in adresses
        }
        self.assertEqual(
            manquants, set(), f"expéditeur affiché qui ne reçoit pas : {manquants}"
        )

    @staticmethod
    def _bloc_service(compose: str, nom: str) -> str:
        """Extrait le bloc d'un service de premier niveau du compose.

        Les services de premier niveau sont indentés sur deux espaces
        (``  admin:``) ; le bloc court jusqu'à la prochaine ligne indentée
        de la même façon.
        """
        import re

        motif = re.compile(r"^  [a-z0-9_-]+:$", re.MULTILINE)
        entete = f"\n  {nom}:\n"
        debut = compose.index(entete)
        apres_entete = debut + len(entete)
        suite = motif.search(compose, apres_entete)
        fin = suite.start() if suite else len(compose)
        return compose[debut:fin]

    def test_admin_recoit_les_memes_variables_d_identite_que_le_collector(
        self,
    ) -> None:
        """La console écrit l'identité active dans instance_identity.

        Ce que « Reprendre la main » y pose vient de l'environnement du
        conteneur admin (cf. identity_environment_defaults côté admin). S'il
        ne porte pas les mêmes variables que le collector, la console
        réécrit des valeurs par défaut codées en dur sur toute la pile —
        y compris maia@sentimail.example, qui cesserait d'être un alias d'action.
        """
        import pathlib
        import re

        compose = (
            pathlib.Path(__file__).resolve().parents[2] / "docker-compose.yml"
        ).read_text("utf-8")
        bloc_collector = self._bloc_service(compose, "collector")
        bloc_admin = self._bloc_service(compose, "admin")
        for variable in ("ACTION_ADDRESS", "ACTION_ALIASES", "ASSISTANT_SENDER"):
            motif = re.compile(rf'^\s*{variable}:\s*"[^"]*"$', re.MULTILINE)
            valeur_collector = motif.search(bloc_collector)
            valeur_admin = motif.search(bloc_admin)
            self.assertIsNotNone(
                valeur_collector, f"{variable} absente du service collector"
            )
            self.assertIsNotNone(
                valeur_admin,
                f"{variable} absente du service admin : la console ('Reprendre "
                "la main') écrirait une valeur par défaut au lieu de la valeur "
                "réellement active",
            )
            self.assertEqual(
                valeur_collector.group().strip(),
                valeur_admin.group().strip(),
                f"{variable} diverge entre collector et admin",
            )


if __name__ == "__main__":
    unittest.main()
