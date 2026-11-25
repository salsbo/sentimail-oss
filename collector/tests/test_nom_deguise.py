"""Le nom affiché écrit pour ressembler à l'organisation revendiquée.

M-8d026c, 25 septembre 2026 : « lnfosPRlME <noreply@a2ztelehealth.com> »
annonce le renouvellement d'un abonnement Prime Video. Deux l minuscules
tiennent la place de deux I, le domaine est authentifié, et le dossier ne
portait qu'une incohérence d'activité : le juge a posé la question.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.organisation_lookup import remembered_apexes
from sentimail_v3.code.sosies import ecriture_du_message, nom_deguise, squelette
from sentimail_v3.observation import deep_analysis
from sentimail_v3.observation.deep_hooks import SenderRelationHook
from sentimail_v3.observation.dossier.hooks.identity import _ascii_identity_markers


class SqueletteTests(unittest.TestCase):
    def test_les_sosies_se_confondent(self) -> None:
        self.assertEqual(squelette("lnfosPRlME"), squelette("InfosPRIME"))
        self.assertEqual(squelette("Arnaz0n"), squelette("amazon"))
        self.assertEqual(squelette("Micr0soft"), squelette("Microsoft"))

    def test_le_deguisement_est_l_ecart_entre_lu_et_ecrit(self) -> None:
        cas = {
            ("lnfosPRlME", "Prime Video"): "prime",
            ("Arnazon Service", "Amazon"): "amazon",
            ("Micr0soft Team", "Microsoft"): "microsoft",
            ("PayPaI", "PayPal"): "paypal",
        }
        for (affiche, revendique), attendu in cas.items():
            with self.subTest(affiche=affiche):
                self.assertEqual(nom_deguise(affiche, revendique), attendu)

    def test_sans_cible_ou_ecrit_en_clair_rien(self) -> None:
        cas = [
            ("lnfosPRlME", ""),
            ("Charlie", "Prime Video"),
            ("Village", "Prime Video"),
            ("Amazon Prime", "Prime Video"),
            ("Annuel-Famille", "Prime Famille"),
            ("LINKEDIN", "LinkedIn"),
            ("Mairie de Sari d'Orcino", "Sarl Theron Plomberie"),
            ("LAFUMA MOBILIER", "Bill Bryan Autos"),
            ("Natural Memory Report", "Comme J'aime"),
        ]
        for affiche, revendique in cas:
            with self.subTest(affiche=affiche, revendique=revendique):
                self.assertEqual(nom_deguise(affiche, revendique), "")


class EcritureDuMessageTests(unittest.TestCase):
    """M-38cfc3, 26 octobre 2026 : « AppIe <noreply@jobfinder.fr> », une
    facture Apple TV. Le lecteur a recopié « AppIe », et DEEP-026 comparait le
    déguisement à lui-même alors que le corps écrivait « Apple »."""

    CORPS = "Votre abonnement Apple TV débute dès aujourd'hui. Apple Distribution International Ltd."

    def test_le_message_ecrit_la_marque_que_le_nom_deguise(self) -> None:
        self.assertEqual(ecriture_du_message("AppIe", self.CORPS), "Apple")
        self.assertEqual(ecriture_du_message("AppIe Services", self.CORPS), "Apple Services")
        self.assertEqual(nom_deguise("AppIe", ecriture_du_message("AppIe", self.CORPS)), "apple")

    def test_un_nom_ecrit_en_clair_ne_prend_jamais_le_sosie(self) -> None:
        self.assertEqual(ecriture_du_message("Apple", "Merci, l'équipe AppIe"), "Apple")

    def test_sans_la_marque_dans_le_texte_le_nom_reste(self) -> None:
        self.assertEqual(ecriture_du_message("AppIe", "Votre facture de 99 €"), "AppIe")
        self.assertEqual(ecriture_du_message("Charlie", "Charlie vous écrit"), "Charlie")


class CaracteresTests(unittest.TestCase):
    def _positions(self, valeur: str, champ: str = "display_name") -> list[int]:
        return [int(m["offset"]) for m in _ascii_identity_markers(valeur, champ)]

    def test_le_l_en_tete_et_entre_majuscules(self) -> None:
        self.assertEqual(self._positions("lnfosPRlME"), [0, 7])
        self.assertEqual(self._positions("lPhone"), [0])

    def test_les_vrais_mots_restent_muets(self) -> None:
        for nom in ("Charlie", "Village", "llama", "Ltd", "WALLMART", "InfosPRIME"):
            with self.subTest(nom=nom):
                self.assertEqual(self._positions(nom), [])

    def test_un_domaine_abrege_n_est_pas_un_deguisement(self) -> None:
        self.assertEqual(self._positions("lnkd", "from_domain"), [])


class MemoireTests(unittest.TestCase):
    MEMOIRE = [
        ("amazon prime video", ["primevideo.com"]),
        ("video prime", ["primevideo.com", "reuters.com"]),
        ("paramount+ on prime video", ["primevideo.com", "paramountplus.com"]),
        ("prime famille", ["famille.fr"]),
    ]

    def test_un_nom_plus_complet_prete_ses_domaines(self) -> None:
        self.assertEqual(remembered_apexes("Prime Video", self.MEMOIRE), ["primevideo.com"])

    def test_un_nom_d_un_seul_mot_n_herite_de_rien(self) -> None:
        self.assertEqual(remembered_apexes("Prime", self.MEMOIRE), [])

    def test_un_domaine_qui_ne_porte_pas_tous_les_mots_est_ecarte(self) -> None:
        self.assertEqual(remembered_apexes("Prime Famille", self.MEMOIRE), [])


class _Pool:
    def __init__(self, rows: list[dict[str, object]] | None = None, panne: bool = False) -> None:
        self.rows = rows or []
        self.panne = panne
        self.motifs: list[str] = []

    async def fetch(self, _sql: str, motifs: list[str]) -> list[dict[str, object]]:
        if self.panne:
            raise RuntimeError("base injoignable")
        self.motifs = motifs
        return self.rows


class LectureMemoireTests(unittest.IsolatedAsyncioTestCase):
    async def test_la_memoire_est_relue(self) -> None:
        from sentimail_v3.observation.organisation_search import _from_memory

        pool = _Pool([{"organisation": "amazon prime video", "apexes": ["primevideo.com"]}])
        self.assertEqual(await _from_memory(pool, "Prime Video"), ["primevideo.com"])  # type: ignore[arg-type]
        self.assertEqual(pool.motifs, ["%prime%", "%video%"])

    async def test_une_memoire_en_panne_ne_rend_rien(self) -> None:
        from sentimail_v3.observation.organisation_search import _from_memory

        self.assertEqual(await _from_memory(_Pool(panne=True), "Prime Video"), [])  # type: ignore[arg-type]


def _contexte(**surcharges: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "pool": None,
        "client": None,
        "settings": SimpleNamespace(search_api_key="cle"),
        "message_id": "m",
        "clue_codes": set(),
        "sender_apex": "a2ztelehealth.com",
        "from_domain": "a2ztelehealth.com",
        "subject": "Martin camille, suite à la fin de l'essai",
        "body": "prime video Notification. Votre abonnement Prime Video a été reconduit.",
        "display_name": "lnfosPRlME",
        "sender_site": None,
        "organisations": {},
        "sender_attested": False,
        "message_purpose": "payment",
    }
    base.update(surcharges)
    return SimpleNamespace(**base)


INCOHERENT = {
    "clue_code": "SENDER_ACTIVITY_INCOHERENT",
    "article_code": "DEEP-019",
    "direction": "adverse",
    "strength": 55,
    "confidence": 0.75,
    "statement": "Le propos de ce message est étranger à l’activité de l’expéditeur.",
    "facts": {},
}


async def _enquete(
    contexte: SimpleNamespace,
    *,
    claim: str = "Prime Video",
    relation: tuple[dict[str, object] | None, dict[str, object]] = (
        None,
        {"searched": True, "rapport": False, "official_apexes": []},
    ),
) -> tuple[list[dict[str, object]], dict[str, object]]:
    async def _claimed(*_: Any, **__: Any):
        return claim, {"asked": True, "read": claim}

    async def _relation(*_: Any, **__: Any):
        return relation

    async def _coherence(*_: Any, **__: Any):
        return dict(INCOHERENT)

    async def _about_domain(*_: Any, **__: Any):
        return [{"url": "https://a2ztelehealth.com", "content": "Elektronik und Wohnen, vom Sofa bis zur Waschmaschine, vom Fahrrad bis zum Handy."}]

    with patch.object(deep_analysis, "_claimed_organisation", _claimed), patch.object(
        deep_analysis, "_identity_relation", _relation
    ), patch.object(deep_analysis, "_activity_coherence", _coherence), patch(
        "sentimail_v3.observation.organisation_search.about_domain", _about_domain
    ):
        return await SenderRelationHook().observe(contexte)  # type: ignore[arg-type]


class EnqueteurTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_nom_deguise_s_ajoute_au_constat(self) -> None:
        clues, facts = await _enquete(_contexte())
        codes = [c["clue_code"] for c in clues]
        self.assertEqual(codes, ["SENDER_RELATION_UNVERIFIED", "IDENTITY_DISPLAY_NAME_DISGUISED"])
        deguise = clues[1]
        self.assertEqual(deguise["direction"], "adverse")
        self.assertEqual(deguise["article_code"], "DEEP-026")
        self.assertEqual(facts["disguised_as"], "prime")

    async def test_avec_le_dementi_le_dossier_dit_la_marque_empruntee(self) -> None:
        """Le cas réel une fois la mémoire relue : primevideo.com est connu, le
        démenti s'écrit, et le nom déguisé le rejoint."""
        refute = {
            "clue_code": "IDENTITY_CLAIMED_ORGANISATION_REFUTED",
            "article_code": "DEEP-022",
            "direction": "adverse",
            "strength": 50,
            "confidence": 0.75,
            "statement": "Le message se présente au nom de Prime Video, depuis un domaine qui ne lui appartient pas.",
            "facts": {"official_apexes": ["primevideo.com"]},
        }
        clues, _ = await _enquete(
            _contexte(),
            relation=(refute, {"searched": True, "official_apexes": ["primevideo.com"]}),
        )
        self.assertEqual(
            [c["clue_code"] for c in clues],
            ["IDENTITY_CLAIMED_ORGANISATION_REFUTED", "IDENTITY_DISPLAY_NAME_DISGUISED"],
        )

    async def test_l_avis_nomme_le_deguisement(self) -> None:
        from sentimail_v3.code.plain_words import _precision

        clues, _ = await _enquete(_contexte())
        phrase = _precision("IDENTITY_DISPLAY_NAME_DISGUISED", clues[1]["facts"])
        self.assertIn("« lnfosPRlME » se lit « prime »", phrase)
        self.assertIn("Prime Video", phrase)

    async def test_un_domaine_qui_appartient_a_l_organisation_l_ecarte(self) -> None:
        clues, _ = await _enquete(
            _contexte(),
            relation=(None, {"searched": True, "cleared": True, "official_apexes": ["a2ztelehealth.com"]}),
        )
        self.assertNotIn("IDENTITY_DISPLAY_NAME_DISGUISED", [c["clue_code"] for c in clues])

    async def test_un_expediteur_atteste_est_note_sans_charge(self) -> None:
        clues, _ = await _enquete(_contexte(sender_attested=True))
        deguise = [c for c in clues if c["clue_code"] == "IDENTITY_DISPLAY_NAME_DISGUISED"]
        self.assertEqual(len(deguise), 1)
        self.assertEqual(deguise[0]["direction"], "neutral")

    async def test_sans_organisation_lue_dans_le_message_rien(self) -> None:
        clues, _ = await _enquete(_contexte(), claim="")
        self.assertNotIn("IDENTITY_DISPLAY_NAME_DISGUISED", [c["clue_code"] for c in clues])

    async def test_le_nom_deguise_recopie_par_le_lecteur_est_lu_dans_le_corps(self) -> None:
        contexte = _contexte(
            display_name="AppIe",
            sender_apex="jobfinder.fr",
            from_domain="jobfinder.fr",
            subject="MARTIN CAMILLE - AGENCE - Abonnemeement facture 99,00 EUR",
            body=EcritureDuMessageTests.CORPS,
        )
        clues, facts = await _enquete(contexte, claim="AppIe")
        self.assertEqual(facts["claimed_organisation"], "Apple")
        self.assertEqual(facts["claim_disguised"], "AppIe")
        self.assertEqual(facts["disguised_as"], "apple")
        self.assertIn("IDENTITY_DISPLAY_NAME_DISGUISED", [c["clue_code"] for c in clues])

    async def test_un_nom_en_clair_n_imite_rien(self) -> None:
        clues, _ = await _enquete(_contexte(display_name="Prime Video"))
        self.assertNotIn("IDENTITY_DISPLAY_NAME_DISGUISED", [c["clue_code"] for c in clues])


class ConvergenceTests(unittest.TestCase):
    def test_le_nom_deguise_en_premier_contact_converge(self) -> None:
        trouves = correlations(
            {"IDENTITY_DISPLAY_NAME_DISGUISED", "HISTORY_FIRST_OBSERVATION", "AUTH_DMARC_PASS"}
        )
        self.assertIn("CORRELATION_BRAND_FIRST_CONTACT", [c["clue_code"] for c in trouves])


if __name__ == "__main__":
    unittest.main()
