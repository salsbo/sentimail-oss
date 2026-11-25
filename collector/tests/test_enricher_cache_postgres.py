"""Cache d'observation testé sur PostgreSQL local, sans toucher au courrier réel.

Les tables temporaires recopient le schéma migré et isolent chaque scénario.
ENRICHER_TEST_DATABASE_URL doit désigner une base explicitement jetable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import asyncpg

from sentimail_v3.observation import enricher
from sentimail_v3.observation.enricher import _next_entities, _reuse, _save

DSN = os.environ.get("ENRICHER_TEST_DATABASE_URL", "")
PARTIELS = {
    "rdap_error": {"rdap_error": {"type": "HTTPStatusError"}},
    "asn_error": {"asn_error": {"type": "Timeout"}},
    "reverse_dns_error": {"reverse_dns_error": {"type": "LifetimeTimeout"}},
    "dns_error": {"dns": {"mx": {"error": "NoNameservers"}}},
}


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class CacheEnrichissementPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        cible = urlsplit(DSN)
        self.assertEqual(cible.hostname, "127.0.0.1")
        self.assertTrue(cible.path.endswith("_test"))
        self.pool = await asyncpg.create_pool(DSN, min_size=1, max_size=1)
        await self.pool.execute(
            "CREATE TEMP TABLE enrichments (LIKE public.enrichments INCLUDING ALL);"
            "CREATE TEMP TABLE entities (LIKE public.entities INCLUDING ALL)"
        )

    async def asyncTearDown(self) -> None:
        await self.pool.close()

    async def occurrence(self, value: str, *, kind: str = "domain", attached=None) -> int:
        return await self.pool.fetchval(
            """INSERT INTO entities
            (message_id,entity_type,role,ordinal,value_raw,value_normalized,enrichment_id)
            VALUES (gen_random_uuid(),$1,'test',1,$2,$2,$3) RETURNING id""",
            kind, value, attached,
        )

    async def observation(
        self, value: str, *, status="ok", age=timedelta(), remaining=timedelta(days=1),
        source="rdap+dns", kind="domain", data=None,
    ) -> int:
        return await self.pool.fetchval(
            """INSERT INTO enrichments
            (entity_type,value_normalized,source,observed_at,expires_at,status,data)
            VALUES ($1,$2,$3,now()-$4::interval,now()+$5::interval,$6,$7::jsonb)
            RETURNING id""",
            kind, value, source, age, remaining, status, json.dumps(data or {}),
        )

    async def test_succes_frais_prioritaire_sur_erreur_et_negatif_plus_recents(self):
        ancien = await self.observation("source.example", remaining=-timedelta(days=1))
        historique = await self.occurrence("source.example", attached=ancien)
        nouveau = await self.occurrence("source.example")
        seconde_occurrence = await self.occurrence("source.example")
        succes = await self.observation(
            "source.example", age=timedelta(days=2), data={"age_days": 123}
        )
        await self.observation("source.example", status="not_found")
        await self.observation("source.example", status="error")
        rows = await _next_entities(self.pool)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["enrichment_id"], succes)
        self.assertTrue(await _reuse(self.pool, "domain", "source.example", succes))
        actual = dict(await self.pool.fetch("SELECT id,enrichment_id FROM entities"))
        self.assertEqual(actual, {historique: ancien, nouveau: succes, seconde_occurrence: succes})
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM enrichments"), 4)
        self.assertEqual(
            await self.pool.fetchval("SELECT data->>'age_days' FROM enrichments WHERE id=$1", succes),
            "123",
        )

    async def test_expiration_source_et_valeur_ne_sont_jamais_confondues(self):
        await self.occurrence("attendue.example")
        await self.observation("attendue.example", remaining=-timedelta(seconds=1))
        autre_source = await self.observation("attendue.example", source="autre")
        autre_valeur = await self.observation("voisine.example")
        autre_type = await self.observation("attendue.example", kind="ip")
        rows = await _next_entities(self.pool)
        self.assertIsNone(rows[0]["enrichment_id"])
        for identifiant in (autre_source, autre_valeur, autre_type):
            self.assertFalse(await _reuse(self.pool, "domain", "attendue.example", identifiant))
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM entities WHERE enrichment_id IS NULL"), 1)

    async def test_expiration_entre_selection_et_rattachement_impose_nouvelle_observation(self):
        await self.occurrence("expire.example")
        identifiant = await self.observation("expire.example")
        self.assertEqual((await _next_entities(self.pool))[0]["enrichment_id"], identifiant)
        await self.pool.execute("UPDATE enrichments SET expires_at=now()-interval '1 second' WHERE id=$1", identifiant)
        self.assertFalse(await _reuse(self.pool, "domain", "expire.example", identifiant))
        self.assertIsNone((await _next_entities(self.pool))[0]["enrichment_id"])

    async def test_boucle_reutilise_cache_sans_dns_rdap_ni_nouvelle_ligne(self):
        await self.occurrence("cache.example")
        identifiant = await self.observation("cache.example")
        settings = SimpleNamespace(database_url=DSN, enrichment_interval_seconds=30)
        # Le premier sommeil suit l'épuisement des attentes : il termine l'essai
        # après la vraie sélection SQL et le vrai rattachement, sans réseau.
        with (
            patch.object(enricher, "load_settings", return_value=settings),
            patch.object(enricher.asyncpg, "create_pool", AsyncMock(return_value=self.pool)),
            patch.object(enricher.httpx, "AsyncClient"),
            patch.object(enricher, "pulse"),
            patch.object(enricher, "_enrich_domain", AsyncMock()) as domaine,
            patch.object(enricher, "_enrich_ip", AsyncMock()) as adresse_ip,
            patch.object(enricher.asyncio, "sleep", AsyncMock(side_effect=asyncio.CancelledError)),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await enricher.main()
        domaine.assert_not_called()
        adresse_ip.assert_not_called()
        self.assertEqual(await self.pool.fetchval("SELECT enrichment_id FROM entities"), identifiant)
        self.assertEqual(await self.pool.fetchval("SELECT count(*) FROM enrichments"), 1)

    async def test_erreur_et_absence_reutilisees_sans_devenir_succes(self):
        for status in ("error", "not_found"):
            value = f"{status}.example"
            await self.occurrence(value)
            await _save(self.pool, "domain", value, status, {}, "source indisponible")
            identifiant = await self.pool.fetchval("SELECT id FROM enrichments WHERE value_normalized=$1", value)
            await self.occurrence(value)
            rows = await _next_entities(self.pool)
            self.assertEqual(rows[0]["enrichment_id"], identifiant)
            self.assertTrue(await _reuse(self.pool, "domain", value, identifiant))
            row = await self.pool.fetchrow("SELECT status,expires_at-observed_at ttl FROM enrichments WHERE id=$1", identifiant)
            self.assertEqual(row["status"], status)
            self.assertAlmostEqual(row["ttl"].total_seconds(), 3600, delta=5)
        self.assertEqual(await _next_entities(self.pool), [])

    async def test_succes_sept_jours_et_nouvelle_observation_apres_expiration(self):
        original = await self.occurrence("frais.example")
        await _save(self.pool, "domain", "frais.example", "ok", {"public_suffix": True})
        row = await self.pool.fetchrow("SELECT id,expires_at-observed_at ttl FROM enrichments")
        self.assertAlmostEqual(row["ttl"].total_seconds(), 7*86400, delta=5)
        await self.pool.execute("UPDATE enrichments SET expires_at=now()-interval '1 second'")
        nouveau = await self.occurrence("frais.example")
        self.assertIsNone((await _next_entities(self.pool))[0]["enrichment_id"])
        await _save(self.pool, "domain", "frais.example", "ok", {"public_suffix": True})
        liens = dict(await self.pool.fetch("SELECT id,enrichment_id FROM entities"))
        self.assertEqual(liens[original], row["id"])
        self.assertNotEqual(liens[nouveau], row["id"])

    async def test_sources_partielles_reessayees_en_une_heure(self):
        for name, data in PARTIELS.items():
            value = f"{name}.example"
            await self.occurrence(value)
            await _save(self.pool, "domain", value, "ok", data)
            row = await self.pool.fetchrow(
                "SELECT status,data,expires_at-observed_at ttl FROM enrichments "
                "WHERE value_normalized=$1", value,
            )
            self.assertEqual(row["status"], "ok")
            self.assertEqual(data, json.loads(row["data"]))
            self.assertAlmostEqual(row["ttl"].total_seconds(), 3600, delta=5)

    async def test_anciennes_observations_partielles_refusees_sans_mutation(self):
        for name, data in PARTIELS.items():
            value = f"{name}.example"
            ancien = await self.observation(
                value, data=data, age=timedelta(hours=2),
                remaining=timedelta(days=6),
            )
            await self.occurrence(value, attached=ancien)
            await self.occurrence(value)
            rows = await _next_entities(self.pool)
            trouvee = next(row for row in rows if row["value_normalized"] == value)
            self.assertIsNone(trouvee["enrichment_id"])
            self.assertFalse(await _reuse(self.pool, "domain", value, ancien))
            self.assertEqual(await self.pool.fetchval(
                "SELECT count(*) FROM entities WHERE enrichment_id=$1", ancien,
            ), 1)
            self.assertGreater(await self.pool.fetchval(
                "SELECT expires_at-now() FROM enrichments WHERE id=$1", ancien,
            ), timedelta(days=5))

    async def test_absence_dns_normale_ne_raccourcit_pas_succes(self):
        for error in ("NXDOMAIN", "NoAnswer"):
            value = f"{error}.example"
            data = {
                "asn_error": {"type": error}, "reverse_dns_error": {"type": error},
                "dns": {"caa": {"error": error}},
            }
            await self.occurrence(value)
            await _save(self.pool, "domain", value, "ok", data)
            row = await self.pool.fetchrow(
                "SELECT id,expires_at-observed_at ttl FROM enrichments WHERE value_normalized=$1",
                value,
            )
            self.assertAlmostEqual(row["ttl"].total_seconds(), 7*86400, delta=5)
            # La même règle doit valoir pour la lecture des snapshots anciens.
            await self.pool.execute(
                "UPDATE enrichments SET observed_at=now()-interval '2 hours' WHERE id=$1", row["id"],
            )
            await self.occurrence(value)
            trouvee = next(row for row in await _next_entities(self.pool) if row["value_normalized"] == value)
            self.assertEqual(trouvee["enrichment_id"], row["id"])
            self.assertTrue(await _reuse(self.pool, "domain", value, row["id"]))

    async def test_selection_bornee_et_valeurs_longues_indexables(self):
        for index in range(25):
            await self.occurrence(f"{index}.example")
        jeton = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(200))
        await self.occurrence("https://" + jeton, kind="url")
        await self.occurrence(jeton + ".example")
        rows = await _next_entities(self.pool)
        self.assertEqual(len(rows), 20)
        self.assertEqual([r["value_normalized"] for r in rows], [f"{i}.example" for i in range(20)])
        self.assertTrue(all(r["enrichment_id"] is None for r in rows))

    async def test_selection_vide_utilise_index_partiel_des_attentes(self):
        # Un historique conséquent et aucune attente reproduisent le scan inutile.
        identifiant = await self.observation("ancien.example")
        await self.pool.execute(
            """INSERT INTO entities
            (message_id,entity_type,role,ordinal,value_raw,value_normalized,enrichment_id)
            SELECT gen_random_uuid(),'domain','test',1,'ancien.example','ancien.example',$1
            FROM generate_series(1,5000)""", identifiant,
        )
        await self.pool.execute("ANALYZE entities")
        plan = await self.pool.fetchval(
            """EXPLAIN (FORMAT JSON) SELECT entity_type,value_normalized,min(id)
            FROM entities WHERE enrichment_id IS NULL AND entity_type IN ('domain','ip')
            GROUP BY entity_type,value_normalized ORDER BY min(id) LIMIT 20"""
        )
        texte = json.dumps(json.loads(plan))
        indexes = await self.pool.fetchval(
            """SELECT array_agg(c.relname) FROM pg_index i
            JOIN pg_class c ON c.oid=i.indexrelid
            WHERE i.indrelid='pg_temp.entities'::regclass
              AND pg_get_expr(i.indpred,i.indrelid) LIKE '%enrichment_id IS NULL%'"""
        )
        self.assertTrue(any(index in texte for index in indexes or []), texte)
        self.assertNotIn('"Node Type": "Seq Scan"', texte)
        self.assertEqual(await _next_entities(self.pool), [])
