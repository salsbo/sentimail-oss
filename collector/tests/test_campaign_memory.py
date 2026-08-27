"""Reconnaître qu'un message reprend un gabarit déjà qualifié.

On mémorise l'empreinte des messages qualifiés (par l'humain ou classés à
haute confiance) ; un nouveau message dont le squelette correspond porte
alors le LABEL de la campagne source, pas un simple score - le juge reçoit
« c'est le gabarit déjà jugé spam le 20/08 », jamais un chiffre opaque.
"""

from __future__ import annotations

import unittest

from sentimail_v3.execution.campaign_memory import (
    match_campaign,
    remember_campaign,
)

GABARIT = """
<html><body><table class="wrap"><tr><td>
<img class="logo" src="https://cdn.evt.com/logo.png">
<h1 class="title">{T}</h1>
<p class="lead">Bonjour {NOM}, votre abonnement.</p>
<div class="card"><span class="amount">69,90</span>
<span class="status">Activé</span></div>
<a class="cta" href="https://evt.com/go?u={ID}">Voir</a>
<ul class="menu"><li>A</li><li>B</li><li>C</li></ul>
<p class="foot">pied</p>
<a class="unsub" href="https://evt.com/u?x={ID}">Désinscription</a>
</td></tr></table></body></html>
"""


def _msg(nom: str, ident: str, titre: str) -> str:
    return GABARIT.replace("{NOM}", nom).replace("{ID}", ident).replace("{T}", titre)


class _FakePool:
    """Un pool en mémoire : deux tables, juste ce que le module interroge."""

    def __init__(self) -> None:
        self.messages: dict[str, tuple[str, str]] = {}
        self.fingerprints: list[dict] = []
        self.buckets: list[tuple[str, int]] = []

    def add_message(self, mid: str, subject: str, html: str) -> None:
        self.messages[mid] = (subject, html)

    async def fetchrow(self, query, *args):
        if "FROM messages" in query:
            mid = args[0]
            if mid not in self.messages:
                return None
            subject, html = self.messages[mid]
            return {"subject": subject, "body_html": html}
        return None

    async def fetch(self, query, *args):
        if "template_lsh_buckets" in query:
            keys = set(args[0])
            ids = {fid for key, fid in self.buckets if key in keys}
            return [
                {
                    "id": fp["id"],
                    "label": fp["label"],
                    "signature": fp["signature"],
                    "subject_template": fp["subject_template"],
                }
                for fp in self.fingerprints
                if fp["id"] in ids
            ]
        return []

    async def fetchval(self, query, *args):
        if "INSERT INTO template_fingerprints" in query:
            fid = len(self.fingerprints) + 1
            self.fingerprints.append(
                {
                    "id": fid,
                    "label": args[1],
                    "signature": list(args[2]),
                    "subject_template": args[3],
                }
            )
            return fid
        return None

    async def execute(self, query, *args):
        if "INSERT INTO template_lsh_buckets" in query:
            for key in args[1]:
                self.buckets.append((key, args[0]))

    def acquire(self):
        pool = self

        class _Ctx:
            async def __aenter__(self):
                return pool

            async def __aexit__(self, *exc):
                return False

        return _Ctx()

    def transaction(self):
        class _Tx:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *exc):
                return False

        return _Tx()


class MemoireDeCampagneTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_exemplaire_du_gabarit_appris_est_reconnu(self) -> None:
        pool = _FakePool()
        pool.add_message("src", "Offre A", _msg("Alex", "aaa1", "Offre A"))
        self.assertTrue(await remember_campaign(pool, "src", "spam"))

        pool.add_message("new", "Offre B", _msg("Camille", "zzz9", "Offre B"))
        match = await match_campaign(pool, "new")
        self.assertIsNotNone(match)
        self.assertEqual(match["label"], "spam")
        self.assertGreaterEqual(match["jaccard"], 0.8)

    async def test_un_autre_gabarit_ne_matche_pas(self) -> None:
        pool = _FakePool()
        pool.add_message("src", "Offre A", _msg("Alex", "aaa1", "Offre A"))
        await remember_campaign(pool, "src", "spam")

        pool.add_message(
            "new", "News",
            "<html><body><div class='n'><section><article><h2>x</h2>"
            "<span>t</span><ul><li>a</li><li>b</li><li>c</li><li>d</li></ul>"
            "<footer><a href='https://autre.fr'>l</a></footer></article>"
            "</section></div></body></html>",
        )
        self.assertIsNone(await match_campaign(pool, "new"))

    async def test_un_message_pauvre_ne_se_memorise_pas(self) -> None:
        pool = _FakePool()
        pool.add_message("src", "x", "<p>Bonjour</p>")
        self.assertFalse(await remember_campaign(pool, "src", "spam"))

    async def test_sans_gabarit_appris_aucun_match(self) -> None:
        pool = _FakePool()
        pool.add_message("new", "Offre", _msg("Alex", "aaa1", "Offre A"))
        self.assertIsNone(await match_campaign(pool, "new"))


if __name__ == "__main__":
    unittest.main()
