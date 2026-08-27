from __future__ import annotations

import unittest

from sentimail_v3.code.organisation import (
    SHARED_DNS_PROVIDERS,
    authentication_signature,
    nameserver_signature,
    same_organisation,
)


class ServeurDeNomsTests(unittest.TestCase):
    """Un domaine qui héberge son propre DNS signe ce qu'il possède.

    Le 18 août, un code de connexion X a attendu cinquante-cinq secondes. La
    voie rapide exige que les liens restent chez l'expéditeur ; ceux-ci
    partaient vers t.co, le raccourcisseur de X lui-même. Vu du seul apex,
    t.co et x.com sont deux tiers.

    Leurs serveurs de noms, eux, disent l'inverse : tous deux délèguent à
    twtrdns.net. Pour faire pointer un domaine vers ces serveurs, il faut
    contrôler ce domaine - la délégation atteste ce qu'aucun certificat
    Let's Encrypt ni aucun RDAP masqué ne dit plus.
    """

    def test_un_dns_auto_heberge_produit_une_signature(self) -> None:
        signature = nameserver_signature(
            ["a.r06.twtrdns.net.", "b.r06.twtrdns.net."]
        )
        self.assertEqual(signature, {"ns:twtrdns.net"})

    def test_deux_domaines_du_meme_operateur_se_reconnaissent(self) -> None:
        t_co = nameserver_signature(["a.r06.twtrdns.net.", "b.r06.twtrdns.net."])
        x_com = nameserver_signature(["a.r10.twtrdns.net.", "b.u10.twtrdns.net."])
        self.assertTrue(same_organisation(t_co, x_com))

    def test_un_hebergeur_mutualise_ne_signe_rien(self) -> None:
        # Des millions de domaines sans rapport partagent ces serveurs :
        # les retenir ferait de tout l'internet une seule maison.
        for mutualise in (
            ["priscilla.ns.cloudflare.com."],
            ["ns-1.awsdns-01.org."],
            ["a3-64.akam.net."],
            ["ns1.ovh.net."],
        ):
            with self.subTest(ns=mutualise[0]):
                self.assertEqual(nameserver_signature(mutualise), set())

    def test_deux_domaines_chez_le_meme_hebergeur_ne_se_reconnaissent_pas(self) -> None:
        mondomaine = nameserver_signature(["priscilla.ns.cloudflare.com."])
        tiers = nameserver_signature(["damian.ns.cloudflare.com."])
        self.assertFalse(same_organisation(mondomaine, tiers))

    def test_une_erreur_de_resolution_ne_signe_rien(self) -> None:
        self.assertEqual(nameserver_signature({"error": "NXDOMAIN"}), set())
        self.assertEqual(nameserver_signature([]), set())
        self.assertEqual(nameserver_signature(None), set())

    def test_les_hebergeurs_repandus_sont_tous_neutralises(self) -> None:
        # On verifie le comportement, pas le contenant : Amazon est couvert
        # par un motif plutot que par une enumeration, que chaque nouvelle
        # extension prendrait en defaut.
        for hote in (
            "ns.cloudflare.com",
            "ns-1.awsdns-01.org",
            "ns-2.awsdns-53.co.uk",
            "a3-64.akam.net",
            "ns1.ovh.net",
            "ns1.gandi.net",
            "ns1-01.azure-dns.com",
        ):
            with self.subTest(hebergeur=hote):
                self.assertEqual(nameserver_signature([hote]), set())

    def test_la_liste_de_reference_n_est_pas_vide(self) -> None:
        self.assertGreater(len(SHARED_DNS_PROVIDERS), 20)


class AuthentificationTests(unittest.TestCase):
    """Le domaine qui signe DKIM engage celui qui possède la clé.

    Une signature DKIM valide prouve que le détenteur du domaine signataire a
    approuvé le message. Deux domaines signés par le même « d= » relèvent donc
    du même maître, sans qu'aucune requête supplémentaire soit nécessaire :
    le fait est déjà dans l'en-tête.
    """

    def test_le_domaine_signataire_produit_une_signature(self) -> None:
        self.assertEqual(
            authentication_signature("x.com", "x.com"), {"dkim:x.com"}
        )

    def test_un_domaine_signataire_different_est_retenu_aussi(self) -> None:
        # Un prestataire d'envoi signe souvent pour son client : les deux
        # domaines relèvent alors du même envoi, ce que le fait doit dire.
        self.assertEqual(
            authentication_signature("news.marque.fr", "marque.fr"),
            {"dkim:marque.fr"},
        )

    def test_sans_signature_dkim_rien_n_est_conclu(self) -> None:
        self.assertEqual(authentication_signature("x.com", ""), set())
        self.assertEqual(authentication_signature("x.com", None), set())

    def test_une_messagerie_publique_ne_signe_aucune_organisation(self) -> None:
        # Tout le monde signe depuis gmail.com : ce n'est pas une organisation.
        self.assertEqual(authentication_signature("moi.fr", "gmail.com"), set())


class CombinaisonTests(unittest.TestCase):
    """Les trois signaux s'additionnent, aucun ne prime sur les autres."""

    def test_deux_signaux_differents_suffisent_chacun(self) -> None:
        par_dns = {"ns:twtrdns.net"}
        par_dkim = {"dkim:x.com"}
        self.assertFalse(same_organisation(par_dns, par_dkim))
        self.assertTrue(same_organisation(par_dns | par_dkim, par_dns))

    def test_deux_signatures_vides_ne_concluent_jamais(self) -> None:
        # L'absence de preuve n'est pas une preuve d'appartenance.
        self.assertFalse(same_organisation(set(), set()))


if __name__ == "__main__":
    unittest.main()


class LectureDesEnrichissementsTests(unittest.IsolatedAsyncioTestCase):
    """Les trois signaux se lisent ensemble, sans requete supplementaire.

    Les serveurs de noms sont deja collectes par l'enrichissement, le domaine
    signataire est deja dans l'en-tete, et le titulaire RDAP etait deja lu.
    Rien de neuf ne part sur le reseau au moment de juger.
    """

    class _Pool:
        def __init__(self, rows):
            self.rows = rows
            self.queries = []

        async def fetch(self, query, *args):
            self.queries.append(query)
            return self.rows

    async def _organisations(self, rows):
        from sentimail_v3.observation.deep_analysis import _domain_organisations

        return await _domain_organisations(self._Pool(rows), "11111111-1111-1111-1111-111111111111")

    async def test_les_serveurs_de_noms_sont_lus(self) -> None:
        organisations = await self._organisations(
            [
                {"domain": "x.com", "rdap": None,
                 "ns": ["a.r10.twtrdns.net."], "dkim_domain": None},
                {"domain": "t.co", "rdap": None,
                 "ns": ["a.r06.twtrdns.net."], "dkim_domain": None},
            ]
        )
        self.assertTrue(
            same_organisation(organisations["x.com"], organisations["t.co"])
        )

    async def test_la_requete_va_chercher_les_ns(self) -> None:
        pool = self._Pool([])
        from sentimail_v3.observation.deep_analysis import _domain_organisations

        await _domain_organisations(pool, "11111111-1111-1111-1111-111111111111")
        self.assertIn("'ns'", pool.queries[0])

    async def test_un_hebergeur_mutualise_ne_rapproche_rien(self) -> None:
        organisations = await self._organisations(
            [
                {"domain": "mondomaine.example", "rdap": None,
                 "ns": ["priscilla.ns.cloudflare.com."], "dkim_domain": None},
                {"domain": "tiers.example", "rdap": None,
                 "ns": ["damian.ns.cloudflare.com."], "dkim_domain": None},
            ]
        )
        self.assertFalse(
            same_organisation(
                organisations.get("mondomaine.example", set()),
                organisations.get("tiers.example", set()),
            )
        )


class VoieRapideBrancheeTests(unittest.IsolatedAsyncioTestCase):
    """La voie rapide recevait un dictionnaire vide, donc ne rapprochait rien.

    Toute la mecanique d'organisation existait, personne ne la lui passait :
    elle appelait apexes_are_close avec {}. Un code X dont les liens partent
    vers t.co etait donc examine par le modele, et livre 55 secondes plus tard.
    """

    def test_la_voie_rapide_recoit_les_organisations(self) -> None:
        import inspect

        from sentimail_v3.judgment import verdict_engine

        source = inspect.getsource(verdict_engine._express_judgment)
        self.assertNotIn("destinations, {})", source)
        self.assertIn("organisations", source)

    def test_le_domaine_signataire_est_lu_depuis_les_indices(self) -> None:
        import inspect

        from sentimail_v3.judgment import verdict_engine

        source = inspect.getsource(verdict_engine._express_judgment)
        self.assertIn("signing_domain", source)


class PasDeCirculariteTests(unittest.TestCase):
    """Une signature ne doit jamais marquer ce qu'elle n'atteste pas.

    Premiere version de ce code : la signature DKIM etait posee sur
    l'expediteur ET sur toutes les destinations. Elles correspondaient alors
    par construction, et la voie rapide s'ouvrait vers n'importe quel tiers.
    Trois tests existants l'ont attrape.
    """

    def test_la_signature_ne_marque_que_l_expediteur_et_le_signataire(self) -> None:
        import inspect

        from sentimail_v3.judgment import verdict_engine

        source = inspect.getsource(verdict_engine._express_judgment)
        marquage = source[source.index("marque = authentication_signature"):]
        marquage = marquage[: marquage.index("reason =")]
        # Les destinations ne doivent pas apparaitre dans la boucle de marquage.
        self.assertNotIn("destinations", marquage)
