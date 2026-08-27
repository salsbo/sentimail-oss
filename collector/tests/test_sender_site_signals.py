from __future__ import annotations

import unittest

from sentimail_v3.observation.deep_analysis import _signals


def _codes(signals: list[dict[str, object]]) -> set[str]:
    return {str(value.get("article_code")) for value in signals}


RESEAU = (
    "Fiore Srl - Soluzioni ICT integrate: distribuzione e supporto per "
    "cablaggio, networking e comunicazione unificata. Chi Siamo Prodotti"
)
MUTUELLE = (
    "Mutuelle santé, prévoyance et retraite complémentaire | Harmonie Mutuelle "
    "Espace personnel Particuliers Entrepreneurs Entreprises ESS Nous découvrir "
    "Suivez-nous sur Instagram LinkedIn Facebook"
)
MEUBLES = (
    "Arredamenti Moreni CUCINA CAMERA DA LETTO CAMERETTA BAGNI SOGGIORNO "
    "COMPLEMENTI D'ARREDO Chi siamo I nostri Brand Progettazione Servizi"
)
FAUX_LAPOSTE = (
    "LA POSTE : notif-colissimo-laposte.info SOCLE NOTIFICATION GROUPE LA "
    "POSTE Infrastructure de routage email transactionnel pour les envois"
)


class SenderSiteSignalTests(unittest.TestCase):
    def test_sans_jugement_aucun_constat_de_metier(self) -> None:
        # Modèle injoignable, site muet, expéditeur déjà connu : dans tous ces
        # cas la question n'a pas été posée, et rien ne doit être affirmé.
        signals = _signals(
            [], [], {}, True,
            sender_apex="fioresrl.com",
            sender_site={"text": RESEAU, "apex": "fioresrl.com"},
            message_registers={"livraison"},
        )
        self.assertNotIn("DEEP-019", _codes(signals))
        self.assertNotIn("DEEP-016", _codes(signals))

    def test_un_metier_non_reconnu_ne_produit_aucun_constat(self) -> None:
        # Le faux positif du 17 août : une mutuelle envoie un code de sécurité,
        # et l'absence de métier reconnu passait pour une contradiction.
        signals = _signals(
            [], [], {}, True,
            sender_apex="harmonie-mutuelle.fr",
            sender_site={"text": MUTUELLE, "apex": "harmonie-mutuelle.fr"},
            message_registers={"paiement"},
        )
        self.assertNotIn("DEEP-016", _codes(signals))
        self.assertNotIn("DEEP-017", _codes(signals))

    def test_un_metier_coherent_ne_produit_rien(self) -> None:
        signals = _signals(
            [], [], {}, True,
            sender_apex="transporteur.fr",
            sender_site={
                "text": "Transport et logistique, suivi de colis, livraison express "
                        "et expédition internationale pour les professionnels",
                "apex": "transporteur.fr",
            },
            message_registers={"livraison"},
        )
        self.assertNotIn("DEEP-016", _codes(signals))

    def test_la_marque_revendiquee_par_la_page_ne_se_constate_plus_ici(self) -> None:
        """Ce constat exigeait une table de marques, supprimée le 27 août.

        Une liste ne connaît que ce qu'on y a mis : elle ignorait « CIC » puis
        « Disney », et accusait « ca-paris.fr » d'usurper le Crédit Agricole
        dont c'est un domaine. La question - ce nom et ce domaine ont-ils un
        rapport ? - se pose désormais sur le nom affiché du message, avec ce
        qu'une recherche rend du nom et du domaine.
        """
        signals = _signals(
            [], [], {}, True,
            sender_apex="notif-colissimo-laposte.info",
            sender_site={"text": FAUX_LAPOSTE, "apex": "notif-colissimo-laposte.info"},
            message_registers={"livraison"},
        )
        # Et la page de couverture ne contredit rien : l'attaquant l'a écrite
        # pour annoncer exactement l'activité dont son message se réclame.
        # Ce montage se prend désormais par le nom affiché, pas par la page.
        self.assertNotIn("DEEP-017", _codes(signals))

    def test_sans_visite_du_site_rien_n_est_affirme(self) -> None:
        signals = _signals(
            [], [], {}, True,
            sender_apex="inconnu.fr",
            sender_site=None,
            message_registers={"livraison"},
        )
        self.assertNotIn("DEEP-016", _codes(signals))
        self.assertNotIn("DEEP-017", _codes(signals))
