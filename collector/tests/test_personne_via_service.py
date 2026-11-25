"""Une personne qui écrit par un service n'est pas une organisation usurpée.

M-633c24, 25 septembre 2026 : « BOURGEOIS Muriel via PRONOTE » depuis le
domaine de l'éditeur du service, message authentifié et légitime. Le nom
affiché entier est parti à la recherche comme une organisation, le site d'un
homonyme (rbourgeois.fr) a été retenu parce qu'il portait un seul des mots, et
DEEP-022 puis CORR-006 ont tiré.

Trois défauts, trois gardes, toutes génériques :

- « X via Y » : c'est Y qui se confronte au domaine ;
- un nom en forme de nom de personne n'est pas posé comme organisation par le
  repli sur le nom affiché ;
- un domaine n'est officiel pour un nom de plusieurs mots que s'il en porte
  plus d'un, ou s'il est l'un d'eux.
"""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from sentimail_v3.code.identity_relation import names_a_person, relayed_organisation
from sentimail_v3.code.organisation_lookup import official_apexes, porte_le_nom
from sentimail_v3.observation import deep_analysis
from sentimail_v3.observation.deep_hooks import SenderRelationHook


def _resultats(*hotes: str) -> list[dict[str, object]]:
    return [{"title": hote, "url": f"https://{hote}/", "content": hote} for hote in hotes]


class RelaisTests(unittest.TestCase):
    def test_via_rend_le_service(self) -> None:
        self.assertEqual(relayed_organisation("BOURGEOIS Muriel via PRONOTE"), "PRONOTE")
        self.assertEqual(relayed_organisation("Gaël Chatelain-Berry via LinkedIn"), "LinkedIn")
        self.assertEqual(relayed_organisation("Jean Dupont (via Google Docs)"), "Google Docs")

    def test_pour_le_compte_de_rend_l_organisation_representee(self) -> None:
        # X agit, Y est celui au nom de qui le message se présente.
        for nom in (
            "Jean Dupont pour le compte de Cabinet Martin",
            "Jean Dupont on behalf of Cabinet Martin",
            "Jean Dupont de la part de Cabinet Martin",
            "Jean Dupont au nom de Cabinet Martin",
        ):
            with self.subTest(nom=nom):
                self.assertEqual(relayed_organisation(nom), "Cabinet Martin")
        self.assertEqual(relayed_organisation("Invitation de la part d'Acme"), "Acme")

    def test_les_formes_commerciales(self) -> None:
        self.assertEqual(relayed_organisation("Tino from n8n"), "n8n")
        self.assertEqual(
            relayed_organisation("Madina chez Mon Cadre Préféré"), "Mon Cadre Préféré"
        )

    def test_un_service_qui_n_est_que_de_l_habillage_rend_le_nom_revendique(self) -> None:
        self.assertEqual(
            relayed_organisation("Service Client Amazon via Email"), "Service Client Amazon"
        )

    def test_sans_relais_le_nom_reste_entier(self) -> None:
        for nom in (
            "DISNEY+ RECOVERY",
            "Crédit Agricole",
            "Viaduc Immobilier",
            "via",
            "Société Fromagère",
            "Newsletter Viadeo",
            "Le Viaduc",
            "Maison Chezaud",
        ):
            with self.subTest(nom=nom):
                self.assertEqual(relayed_organisation(nom), nom)


class NomDePersonneTests(unittest.TestCase):
    def test_nom_en_capitales_et_prenom(self) -> None:
        for nom in ("BOURGEOIS Muriel", "Philippe DUVAL", "Sophie BLET", "CHEN Si"):
            with self.subTest(nom=nom):
                self.assertTrue(names_a_person(nom))

    def test_civilite_et_initiale(self) -> None:
        self.assertTrue(names_a_person("Dr. Daniel Foster"))
        self.assertTrue(names_a_person("Mme Claire Durand"))
        self.assertTrue(names_a_person("Paige B"))

    def test_l_adresse_qui_separe_les_noms(self) -> None:
        self.assertTrue(names_a_person("Muriel Bourgeois", "muriel.bourgeois@exemple.test"))
        self.assertTrue(names_a_person("Sophia Wong", "sophia.wong@exemple.test"))

    def test_l_adresse_initiale_et_nom(self) -> None:
        # M-e36c20, 15 octobre 2026 : « Eva Lambertini <elambertini@prestataire.example> »
        # a été cherchée comme une organisation, sans rapport trouvé avec son
        # propre employeur. L'initiale collée au nom est la convention des
        # messageries d'entreprise.
        for nom, adresse in (
            ("Eva Lambertini", "elambertini@prestataire.example"),
            ("Sonia Belkadi", "sbelkadi@prestataire.example"),
            ("Jean Durand", "durandj@exemple.test"),
            ("Élodie Évrard", "eevrard@exemple.test"),
        ):
            with self.subTest(nom=nom):
                self.assertTrue(names_a_person(nom, adresse))

    def test_l_initiale_ne_suffit_pas_devant_un_mot_court_ou_seul(self) -> None:
        for nom, adresse in (
            ("Dash Cam", "dcam@exemple.test"),
            ("Eva Lambertini", "lambertini@prestataire.example"),
            ("Eva Lambertini", "contact@prestataire.example"),
        ):
            with self.subTest(nom=nom, adresse=adresse):
                self.assertFalse(names_a_person(nom, adresse))

    def test_une_marque_n_est_pas_une_personne(self) -> None:
        for nom, adresse in (
            ("DISNEY+ RECOVERY", ""),
            ("Cession PME", ""),
            ("BNP Paribas", ""),
            ("USPS Customer Care", ""),
            ("NASA Space Apps", ""),
            ("HP Online Store", ""),
            ("Doctolib", "doctolib@exemple.test"),
            ("Dash Cam", "DashCam@exemple.test"),
            ("Pharmacie Lafayette", "Pharmacie@exemple.test"),
            ("Uber Eats", "uber@uber.com"),
            ("C I C", ""),
            ("Prime Video", ""),
            ("Dr. Martens", ""),
            ("Mr Bricolage", ""),
        ):
            with self.subTest(nom=nom):
                self.assertFalse(names_a_person(nom, adresse))

    def test_prenom_et_nom_sans_indice_restent_dans_le_doute(self) -> None:
        # Indiscernable de « Grandir Ensemble » : cherché, et c'est le filtre
        # des domaines officiels qui protège.
        self.assertFalse(names_a_person("Muriel Bourgeois", "pronote@exemple.test"))


class DomaineQuiPorteLeNomTests(unittest.TestCase):
    def test_un_seul_mot_d_un_nom_compose_ne_suffit_plus(self) -> None:
        self.assertFalse(porte_le_nom("rbourgeois", "BOURGEOIS Muriel"))
        self.assertFalse(porte_le_nom("philduval", "Philippe DUVAL"))
        self.assertFalse(porte_le_nom("menardgroup", "Louis MENARD"))
        self.assertEqual(
            official_apexes(_resultats("rbourgeois.fr"), organisation="Muriel Bourgeois"), []
        )

    def test_deux_mots_ou_rien_que_des_morceaux_du_nom(self) -> None:
        for etiquette, nom in (
            ("creditagricole", "Crédit Agricole d'Ile-de-France"),
            ("primevideo", "Prime Video"),
            ("bnpparibas", "BNP Paribas"),
            ("lidl", "Lidl France"),
            ("laposte", "La Poste-Colissimo"),
            ("samsclub", "Sam's Club Member Services"),
            ("canalplus", "Ne manquez pas l’enquête Canal+"),
        ):
            with self.subTest(nom=nom):
                self.assertTrue(porte_le_nom(etiquette, nom))

    def test_deux_mots_qui_se_chevauchent_n_en_font_qu_un(self) -> None:
        self.assertFalse(porte_le_nom("mariettedeco", "Mariette Marie"))

    def test_un_nom_d_un_mot_garde_la_regle_d_avant(self) -> None:
        self.assertTrue(porte_le_nom("disneyplus", "DISNEY+ RECOVERY"))
        self.assertEqual(
            official_apexes(_resultats("rbourgeois.fr"), organisation="PRONOTE"), []
        )


APEX_EDITEUR = "editeur-scolaire.net"


def _contexte(display_name: str, **surcharges: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "pool": None,
        "client": None,
        "settings": SimpleNamespace(search_api_key="cle"),
        "message_id": "m",
        "clue_codes": set(),
        "sender_apex": APEX_EDITEUR,
        "from_domain": APEX_EDITEUR,
        "from_address": "service@" + APEX_EDITEUR,
        "subject": "Nouveau message",
        "body": "Bonjour, la sortie de jeudi est reportée. Cordialement.",
        "display_name": display_name,
        "sender_site": None,
        "organisations": {},
        "sender_attested": False,
        "message_purpose": "",
    }
    base.update(surcharges)
    return SimpleNamespace(**base)


class _Monde:
    """La recherche et les modèles, simulés ; le reste du trajet est réel.

    La recherche sur un nom rend toujours le site d'un homonyme qui porte le
    nom de famille, plus ce qu'on lui ajoute ; le filtre des domaines officiels
    est le vrai. Le modèle de rapport répond « aucun rapport » : c'est ce qu'il
    a répondu pour M-633c24.
    """

    def __init__(self, *, claim: str = "", sur_le_nom: tuple[str, ...] = ()) -> None:
        self.claim = claim
        self.sur_le_nom = ("rbourgeois.fr",) + sur_le_nom
        self.cherches: list[str] = []

    async def _claimed(self, *_: Any, **__: Any):
        return self.claim, {"asked": True, "read": self.claim}

    async def _about_name(self, _pool, _client, _settings, nom: str):
        self.cherches.append(nom)
        resultats = _resultats(*self.sur_le_nom)
        return resultats, official_apexes(resultats, organisation=nom)

    async def _about_domain(self, *_: Any, **__: Any):
        return _resultats(APEX_EDITEUR)

    async def _chat(self, *_: Any, **__: Any):
        return json.dumps({"rapport": False, "organisation": "", "explication": "Sans rapport."}), {}

    async def _coherence(self, *_: Any, **__: Any):
        return None

    async def run(self, contexte: SimpleNamespace):
        with patch.object(deep_analysis, "_log", lambda *a, **k: None), patch.object(
            deep_analysis, "_claimed_organisation", self._claimed
        ), patch.object(deep_analysis, "provider_chat_json", self._chat), patch.object(
            deep_analysis, "_activity_coherence", self._coherence
        ), patch(
            "sentimail_v3.observation.organisation_search.about_name", self._about_name
        ), patch(
            "sentimail_v3.observation.organisation_search.about_domain", self._about_domain
        ):
            clues, facts = await SenderRelationHook().observe(contexte)  # type: ignore[arg-type]
        self.facts = facts
        return [str(clue.get("article_code")) for clue in clues]


class PersonneViaServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_personne_via_le_service_ne_fait_pas_tirer_deep_022(self) -> None:
        """M-633c24 : seul le service est cherché, et l'homonyme n'est pas retenu."""
        monde = _Monde()
        articles = await monde.run(_contexte("BOURGEOIS Muriel via PRONOTE"))
        self.assertNotIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, ["PRONOTE"])
        self.assertEqual(monde.facts["claimed_organisation"], "PRONOTE")

    async def test_le_modele_qui_recopie_le_nom_entier_est_ramene_au_service(self) -> None:
        monde = _Monde(claim="BOURGEOIS Muriel via PRONOTE")
        articles = await monde.run(_contexte("BOURGEOIS Muriel via PRONOTE"))
        self.assertNotIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, ["PRONOTE"])
        self.assertEqual(monde.facts["claim_source"], "content")

    async def test_la_personne_seule_n_est_pas_cherchee(self) -> None:
        monde = _Monde()
        articles = await monde.run(_contexte("BOURGEOIS Muriel"))
        self.assertNotIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, [])
        self.assertEqual(monde.facts["claim_refused"], "person_name")
        self.assertEqual(monde.facts["claimed_organisation"], "")

    async def test_la_personne_de_l_adresse_d_entreprise_n_est_pas_cherchee(self) -> None:
        """M-e36c20 : le nom d'une salariée n'est pas une organisation à confronter."""
        monde = _Monde()
        await monde.run(
            _contexte(
                "Eva Lambertini",
                from_address="elambertini@prestataire.example",
                sender_apex="prestataire.example",
                from_domain="prestataire.example",
            )
        )
        self.assertEqual(monde.cherches, [])
        self.assertEqual(monde.facts["claim_refused"], "person_name")

    async def test_prenom_et_nom_cherches_ne_pretent_pas_l_homonyme(self) -> None:
        monde = _Monde()
        articles = await monde.run(_contexte("Muriel Bourgeois"))
        self.assertEqual(monde.cherches, ["Muriel Bourgeois"])
        self.assertNotIn("DEEP-022", articles)

    async def test_la_personne_dont_le_domaine_porte_le_nom_reste_concordante(self) -> None:
        monde = _Monde()
        articles = await monde.run(
            _contexte("Elisabeth MARTIN", sender_apex="example.org", from_domain="example.org")
        )
        self.assertEqual(monde.facts["outcome"], "SENDER_RELATION_CONSISTENT")
        self.assertNotIn("DEEP-022", articles)


class UsurpateurTests(unittest.IsolatedAsyncioTestCase):
    """Les gardes ne doivent pas ouvrir la porte au montage qu'elles côtoient."""

    DOMAINE = "boutique-sans-rapport.top"

    def _contexte(self, display_name: str, body: str) -> SimpleNamespace:
        return _contexte(
            display_name,
            sender_apex=self.DOMAINE,
            from_domain=self.DOMAINE,
            from_address="noreply@" + self.DOMAINE,
            body=body,
        )

    async def test_la_marque_lue_dans_le_message_tire_toujours(self) -> None:
        monde = _Monde(claim="Amazon", sur_le_nom=("amazon.fr",))
        articles = await monde.run(
            self._contexte(
                "Service Client Amazon via Paiement",
                "Amazon : votre compte est suspendu, confirmez votre carte.",
            )
        )
        self.assertIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, ["Amazon"])

    async def test_le_repli_sur_le_nom_affiche_tire_toujours(self) -> None:
        monde = _Monde(sur_le_nom=("amazon.fr",))
        articles = await monde.run(
            self._contexte("Service Client Amazon via Email", "Votre compte est suspendu.")
        )
        self.assertIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, ["Service Client Amazon"])

    async def test_le_service_revendique_est_confronte_au_domaine(self) -> None:
        # « X via Y » : c'est Y qui est revendiqué, et Y n'écrit pas d'ici.
        monde = _Monde(sur_le_nom=("paypal.fr",))
        articles = await monde.run(
            self._contexte("Service Client Amazon via PayPal", "Votre compte est suspendu.")
        )
        self.assertIn("DEEP-022", articles)
        self.assertEqual(monde.cherches, ["PayPal"])


if __name__ == "__main__":
    unittest.main()
