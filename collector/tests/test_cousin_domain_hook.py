"""L'enquêteur qui compare l'adresse d'envoi aux domaines officiels connus.

Il relit la mémoire des recherches (`organisation_lookups`) et ne sort jamais :
un domaine sosie se constate sur ce que la recherche a déjà établi. Tous les
domaines de ce fichier sont fictifs.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

from sentimail_v3.observation.deep_hooks import (
    DEEP_HOOKS,
    CousinDomainHook,
    run_deep_hooks,
)


class _Pool:
    """La mémoire des recherches, telle que la table la rend."""

    def __init__(self, lignes: list[dict[str, object]] | None = None, *, panne: bool = False) -> None:
        self.lignes = lignes or []
        self.panne = panne

    async def fetch(self, _sql: str, *_args: object) -> list[dict[str, object]]:
        if self.panne:
            raise ConnectionError("base injoignable")
        return self.lignes


_MEMOIRE = [{"organisation": "exemple banque", "apexes": ["exemplebanque.fr"]}]


def _contexte(**surcharges: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "pool": _Pool(_MEMOIRE),
        "sender_apex": "exemp1ebanque.fr",
        "from_domain": "exemp1ebanque.fr",
        "organisations": {},
        "sender_attested": False,
    }
    base.update(surcharges)
    return SimpleNamespace(**base)


class RegistreTests(unittest.TestCase):
    def test_le_hook_suit_sender_relation_au_registre(self) -> None:
        # sender_relation écrit en mémoire les domaines de la revendication
        # courante : passé après lui, cousin_domain les compare aussi.
        noms = [hook.name for hook in DEEP_HOOKS]
        self.assertEqual(noms.index("cousin_domain"), noms.index("sender_relation") + 1)


class CousinDomainHookTests(unittest.IsolatedAsyncioTestCase):
    async def test_un_domaine_sosie_est_accuse(self) -> None:
        clues, facts = await CousinDomainHook().observe(_contexte())
        self.assertEqual(len(clues), 1)
        clue = clues[0]
        self.assertEqual(clue["clue_code"], "IDENTITY_COUSIN_DOMAIN")
        self.assertEqual(clue["article_code"], "IDENTITY-010")
        self.assertEqual(clue["direction"], "adverse")
        self.assertEqual(clue["strength"], 65)
        self.assertEqual(clue["facts"]["imite"], "exemplebanque.fr")
        # Le message peut ne rien revendiquer : la carte « Se présente comme »
        # ne doit pas se faire sur ce constat.
        self.assertNotIn("claimed_organisation", clue["facts"])
        self.assertEqual(facts["imite"], "exemplebanque.fr")
        self.assertEqual(facts["compared"], 1)

    async def test_un_expediteur_atteste_est_note_sans_charge(self) -> None:
        clues, _ = await CousinDomainHook().observe(_contexte(sender_attested=True))
        self.assertEqual(len(clues), 1)
        self.assertEqual(clues[0]["direction"], "neutral")
        self.assertEqual(clues[0]["strength"], 0)
        self.assertIs(clues[0]["facts"]["attested_locally"], True)

    async def test_un_fait_de_propriete_innocente(self) -> None:
        clues, facts = await CousinDomainHook().observe(
            _contexte(organisations={"exemp1ebanque.fr": {"ns:exemplebanque.fr"}})
        )
        self.assertEqual(clues, [])
        self.assertEqual(facts["owned_via"], "exemplebanque.fr")

    async def test_un_domaine_officiel_n_imite_personne(self) -> None:
        # Une recherche a établi ce domaine officiel sous son propre nom : il
        # répond de lui-même, même si sa graphie se lit comme un autre.
        memoire = _MEMOIRE + [
            {"organisation": "exemp1ebanque", "apexes": ["exemp1ebanque.fr"]}
        ]
        clues, facts = await CousinDomainHook().observe(_contexte(pool=_Pool(memoire)))
        self.assertEqual(clues, [])
        self.assertIs(facts["sender_official"], True)

    async def test_une_memoire_illisible_ne_produit_rien(self) -> None:
        resultats = await run_deep_hooks(
            [CousinDomainHook()], _contexte(pool=_Pool(panne=True))
        )
        self.assertEqual(resultats[0].status, "error")
        self.assertEqual(resultats[0].clues, [])

    async def test_sans_domaine_rien_ne_se_compare(self) -> None:
        resultats = await run_deep_hooks([CousinDomainHook()], _contexte(sender_apex=""))
        self.assertEqual(resultats[0].status, "skip")
        self.assertEqual(resultats[0].facts, {"compared": 0})


if __name__ == "__main__":
    unittest.main()
