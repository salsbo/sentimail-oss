"""Les serveurs SMTP qui livrent du spam confirmé laissent leur adresse.

Chaque classement en indésirable et chaque qualification humaine de spam
gardent l'IP source dans hostile_smtp_sources : une réputation interne,
construite sur nos seules observations - rien ne sort, conformément à la
décision « pas de réputation externe ». La liste sert de cache consultable,
et pourra plus tard nourrir un blocage au niveau de Postfix.
"""

from __future__ import annotations

import unittest

from sentimail_v3.execution.hostile_sources import (
    is_recordable_ip,
    record_hostile_source,
)


class AdressesEnregistrablesTests(unittest.TestCase):
    def test_une_ip_publique_s_enregistre(self) -> None:
        # 203.0.113.x et 2001:db8:: sont des plages de documentation, marquées
        # privées par ipaddress : de vraies adresses publiques ici.
        for ip in ("8.8.8.8", "93.184.216.8", "2a00:1450:4007::4"):
            with self.subTest(ip=ip):
                self.assertTrue(is_recordable_ip(ip))

    def test_les_adresses_internes_ne_s_enregistrent_jamais(self) -> None:
        # Le relais interne, la sonde e2e et le LAN passent par ces plages :
        # les inscrire ferait bloquer sa propre infrastructure.
        for ip in (
            "127.0.0.1",
            "10.0.0.4",
            "192.168.50.73",
            "172.16.4.2",
            "100.100.50.50",
            "fe80::1",
            "::1",
        ):
            with self.subTest(ip=ip):
                self.assertFalse(is_recordable_ip(ip))

    def test_une_valeur_illisible_ne_s_enregistre_pas(self) -> None:
        for valeur in ("", "pas-une-ip", None):
            with self.subTest(valeur=valeur):
                self.assertFalse(is_recordable_ip(valeur))


class EnregistrementTests(unittest.IsolatedAsyncioTestCase):
    def _pool(self, ip):
        appels = []

        class _Pool:
            async def fetchval(self, query, *args):
                return ip

            async def fetch(self, query, *args):
                # Pas de chaîne Received dans ces cas : le repli ne trouve rien.
                return []

            async def execute(self, query, *args):
                appels.append((query, args))

        return _Pool(), appels

    async def test_une_source_hostile_est_conservee(self) -> None:
        pool, appels = self._pool("93.184.216.8")
        fait = await record_hostile_source(pool, "message-id", "verdict_spam")
        self.assertTrue(fait)
        self.assertEqual(len(appels), 1)
        query, args = appels[0]
        self.assertIn("hostile_smtp_sources", query)
        self.assertIn("93.184.216.8", args)
        self.assertIn("verdict_spam", args)

    async def test_une_source_interne_est_ignoree(self) -> None:
        pool, appels = self._pool("100.100.50.50")
        fait = await record_hostile_source(pool, "message-id", "verdict_spam")
        self.assertFalse(fait)
        self.assertEqual(appels, [])

    async def test_sans_ip_rien_ne_s_ecrit(self) -> None:
        pool, appels = self._pool(None)
        fait = await record_hostile_source(pool, "message-id", "verdict_spam")
        self.assertFalse(fait)
        self.assertEqual(appels, [])


if __name__ == "__main__":
    unittest.main()


class SourceReelleTests(unittest.IsolatedAsyncioTestCase):
    """L'IP du pair SMTP du collector est le MX interne, jamais la source.

    Constaté au backfill du 20/08 : 143 spams qualifiés, 0 IP enregistrée -
    smtp_peer_ip porte l'adresse Docker du relais interne (192.168.x). La
    source réelle est dans le Received écrit par le MX frontal : la première
    adresse publique de la chaîne est celle du client qui nous a livré.
    """

    def _pool(self, peer_ip, received):
        appels = []

        class _Pool:
            async def fetchval(self, query, *args):
                return peer_ip

            async def fetch(self, query, *args):
                if "received" in query.casefold():
                    return [{"value_decoded": v} for v in received]
                return []

            async def execute(self, query, *args):
                appels.append((query, args))

        return _Pool(), appels

    async def test_le_repli_received_trouve_la_source_publique(self) -> None:
        pool, appels = self._pool(
            "192.168.192.11",
            [
                "from mx (mx.sentinel.mondomaine.example [192.168.192.11]) by collector; "
                "Wed, 20 Aug 2026 20:00:00 +0000",
                "from mail-sender.example (unknown [93.184.216.7]) by "
                "mx.sentinel.mondomaine.example; Wed, 20 Aug 2026 19:59:59 +0000",
            ],
        )
        fait = await record_hostile_source(pool, "message-id", "verdict_spam")
        self.assertTrue(fait)
        self.assertEqual(len(appels), 1)
        self.assertIn("93.184.216.7", appels[0][1])

    async def test_sans_ip_publique_rien_ne_s_ecrit(self) -> None:
        pool, appels = self._pool(
            "192.168.192.11",
            ["from a (b [10.0.0.4]) by mx; Wed, 20 Aug 2026 19:00:00 +0000"],
        )
        self.assertFalse(await record_hostile_source(pool, "m", "verdict_spam"))
        self.assertEqual(appels, [])


class RdnsTests(unittest.IsolatedAsyncioTestCase):
    """Le PTR que le MX a déjà résolu accompagne l'adresse au registre.

    Postfix écrit « from HELO (ptr [ip]) » dans son Received : le rDNS est
    donc déjà sous la main, sans aucune requête sortante. « unknown » ne vaut
    rien et reste vide.
    """

    def _pool(self, received):
        appels = []

        class _Pool:
            async def fetchval(self, query, *args):
                return "192.168.192.11"

            async def fetch(self, query, *args):
                return [{"value_decoded": v} for v in received]

            async def execute(self, query, *args):
                appels.append((query, args))

        return _Pool(), appels

    async def test_le_rdns_est_conserve_avec_l_adresse(self) -> None:
        pool, appels = self._pool(
            [
                "from mx (mx.sentinel.mondomaine.example [192.168.192.11]) by collector; x",
                "from spam.example (mail.badhost.example [93.184.216.8]) by "
                "mx.sentinel.mondomaine.example; x",
            ]
        )
        self.assertTrue(await record_hostile_source(pool, "m", "verdict_spam"))
        query, args = appels[0]
        self.assertIn("rdns", query)
        self.assertIn("mail.badhost.example", args)

    async def test_un_ptr_unknown_reste_vide(self) -> None:
        pool, appels = self._pool(
            ["from spam.example (unknown [93.184.216.8]) by mx.sentinel; x"]
        )
        self.assertTrue(await record_hostile_source(pool, "m", "verdict_spam"))
        _, args = appels[0]
        self.assertNotIn("unknown", args)
