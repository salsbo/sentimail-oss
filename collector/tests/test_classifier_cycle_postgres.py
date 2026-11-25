"""Intégration sur une base jetable nommée explicitement, jamais sur la production."""

import json
import os
import unittest
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

import asyncpg

from sentimail_v3.judgment.classifier_runtime import corpus_fingerprint
from sentimail_v3.supervision.classifier import configure
from sentimail_v3.supervision.classifier_cycle import LOCK_ID, run_once
from sentimail_v3.supervision.training import SCHEMA, compact_dossier, fingerprint
from test_local_classifier import artifact, dossier


@unittest.skipUnless(os.environ.get("CLASSIFIER_TEST_DATABASE_URL"), "base PostgreSQL jetable requise")
class CyclePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_cycle_reproductible_revue_et_refus_d_activation(self):
        dsn = os.environ["CLASSIFIER_TEST_DATABASE_URL"]
        target = urlsplit(dsn)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertEqual(target.path, "/sentimail_classifier_test")
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        try:
            message = await pool.fetchval("""INSERT INTO messages
                (ingest_key,envelope_from,envelope_recipients,raw_eml,raw_sha256,raw_size_bytes,
                 headers_size_bytes,body_size_bytes,line_count,max_line_length,contains_8bit,contains_nul,
                 line_ending,root_content_type,parser_version,body_text)
                VALUES ('classifier-fixture','sender@example.test','{}','test',repeat('a',64),4,
                        0,4,1,4,false,false,'CRLF','text/plain','test','Courrier fictif de test') RETURNING id""")
            samples = []
            for index in range(100):
                value = dossier()
                value["clues"].append(dict(value["clues"][0], clue_code=f"INDEX_{index}", direction="neutral"))
                canonical = compact_dossier(value)
                samples.append(await pool.fetchval("""INSERT INTO training_samples
                    (message_id,kind,dossier,dossier_sha256,schema_version,teacher_provider,teacher_target)
                    VALUES ($1,'form_example',$2::jsonb,$3,$4,'deepseek',$5::jsonb) RETURNING id""",
                    message if index == 0 else None, json.dumps(canonical), fingerprint(canonical), SCHEMA,
                    json.dumps({"classification": "legitimate" if index % 2 else "spam",
                                "delivery_decision": "deliver" if index % 2 else "junk"})))
            base = artifact()
            base["threshold"] = .999
            base["corpus_sha256"] = await corpus_fingerprint(pool)
            active = await configure(pool, artifact=base)
            initial_id = active["model_id"]
            await pool.execute("UPDATE classifier_automation SET enabled=true,auto_activate=true")
            conflicting = await pool.fetchval("""INSERT INTO training_samples
                (kind,dossier,dossier_sha256,schema_version)
                SELECT 'ground_truth',dossier,dossier_sha256,schema_version FROM training_samples WHERE id=$1
                RETURNING id""", samples[1])
            for label in ('spam', 'legitimate'):
                label_id = await pool.fetchval("""INSERT INTO labels(source,label,is_ground_truth)
                    VALUES ('smtp_feedback_user',$1,true) RETURNING id""", label)
                await pool.execute("""INSERT INTO training_sample_annotations
                    (sample_id,label_id,label,source,authority,scope,labelled_at)
                    VALUES ($1,$2,$3,'smtp_feedback_user','user','mailbox_preference',now())""",
                    conflicting, label_id, label)
            # Label ancien sans snapshot : conservé, exclu, jamais promu expert.
            await pool.execute("""INSERT INTO labels(message_id,source,label,is_ground_truth)
                VALUES ($1,'smtp_feedback_user','spam',true)""", message)
            first = await run_once(pool, force=True)
            self.assertTrue(first["trained"])
            self.assertEqual(len(first["exclusions"]["mailbox_labels_without_dossier"]), 1)
            self.assertEqual(first["exclusions"]["preference_conflicts"], [conflicting])
            self.assertEqual(first["source_quality"]["conflicting_samples"], 1)
            self.assertEqual(first["mode"], "shadow")
            self.assertEqual(first["active_model_id"], initial_id)
            self.assertEqual(await pool.fetchval("SELECT artifact->>'threshold' FROM classifier_models WHERE model_id=$1", first["candidate_model_id"]), '0.999')
            second = await run_once(pool, force=True)
            self.assertFalse(second["trained"])
            self.assertEqual(second["candidate_model_id"], first["candidate_model_id"])
            # Une migration du Code suffit à rendre le cycle exigible sous
            # 24 h, sans correction A/B et sans activation d'un candidat refusé.
            await pool.execute("""UPDATE code_articles SET principle=principle || ' test corpus'
                WHERE ctid IN (SELECT ctid FROM code_articles LIMIT 1)""")
            corpus_cycle = await run_once(pool)
            self.assertTrue(corpus_cycle["trained"])
            self.assertNotEqual(corpus_cycle["candidate_model_id"], first["candidate_model_id"])
            self.assertEqual(corpus_cycle["active_model_id"], initial_id)
            self.assertEqual(await run_once(pool), {"status": "not_due"})
            with self.assertRaisesRegex(ValueError, "activation refusée"):
                await configure(pool, mode="enforced")
            # Un A/B hors revue déclenche bien un cycle sans --force sous 24 h.
            await pool.execute("INSERT INTO labels(source,label,is_ground_truth) VALUES ('smtp_feedback_user','spam',true)")
            feedback_cycle = await run_once(pool)
            self.assertTrue(feedback_cycle['trained'])
            self.assertNotEqual(first['feedback_revision'], feedback_cycle['feedback_revision'])
            q = await pool.fetchrow("SELECT * FROM classifier_review_queue WHERE sample_id=$1", samples[0])
            self.assertIsNotNone(q)
            await pool.execute("""UPDATE classifier_review_queue SET status='submitted',label='spam',
                reason_code='confirmed_spam',operator='human-test-fixture',submitted_at=now() WHERE id=$1""", q["id"])
            third = await run_once(pool)
            self.assertEqual(third["reviews_applied"], 1)
            self.assertEqual(await pool.fetchval("SELECT status FROM classifier_review_queue WHERE id=$1", q["id"]), "done")
            self.assertEqual(await pool.fetchval("SELECT count(*) FROM labels WHERE source='expert_adjudication'"), 1)
            await run_once(pool)
            self.assertEqual(await pool.fetchval("SELECT count(*) FROM labels WHERE source='expert_adjudication'"), 1)
            async with pool.acquire() as lock:
                await lock.execute("SELECT pg_advisory_lock($1)", LOCK_ID)
                self.assertEqual(await run_once(pool, force=True), {"status": "busy"})
                await lock.execute("SELECT pg_advisory_unlock($1)", LOCK_ID)
            with patch("sentimail_v3.supervision.classifier_cycle.export", AsyncMock(side_effect=RuntimeError("test"))):
                with self.assertRaises(RuntimeError):
                    await run_once(pool, force=True)
            self.assertEqual(await pool.fetchval("SELECT status FROM classifier_automation"), "error")
            self.assertEqual(await pool.fetchval("SELECT mode FROM classifier_config"), "shadow")
            await configure(pool, mode="off")
            with self.assertRaisesRegex(ValueError, "configuration modifiée"):
                await configure(pool, mode="enforced", automated=True, expected=(initial_id, "shadow"))
            self.assertEqual(await pool.fetchval("SELECT mode FROM classifier_config"), "off")
            # Qualification sans annotations expertes ni 300 observations réelles.
            from test_local_classifier import llm_artifact
            from sentimail_v3.supervision.classifier_cycle import advance
            qualified = llm_artifact()
            qualified['corpus_sha256'] = await corpus_fingerprint(pool)
            await configure(pool, mode='shadow')
            state = await advance(pool, qualified, auto_activate=True)
            self.assertEqual(state['mode'], 'enforced')
            self.assertEqual(state['shadow']['eligible_groups'], 0)
        finally:
            await pool.close()
