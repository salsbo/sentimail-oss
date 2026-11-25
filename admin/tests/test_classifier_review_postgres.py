"""La revue lit la vue persistée sans réinterpréter le MIME alternatif."""

import json
import os
import unittest
from urllib.parse import urlsplit

import asyncpg

from sentimail_admin.classifier_review import review_content, sample_page, sample_query

DSN = os.environ.get("REVIEW_TEST_DATABASE_URL", "")


@unittest.skipUnless(DSN, "base PostgreSQL locale jetable requise")
class RevuePostgresTests(unittest.IsolatedAsyncioTestCase):
    async def test_vue_versionnee_prioritaire_et_texte_expire_non_requalifiable(self):
        target = urlsplit(DSN)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertTrue(target.path.endswith("_test"))
        connection = await asyncpg.connect(DSN)
        try:
            await connection.execute("""
                CREATE TEMP TABLE messages(id integer,subject text,from_header text,
                    body_text text,body_html text,redacted_at timestamptz,facts jsonb);
                CREATE TEMP TABLE classifier_review_queue(id integer,sample_id integer,
                    partition text,status text);
                CREATE TEMP TABLE training_samples(id integer,message_id integer,dossier jsonb);
                CREATE TEMP TABLE external_analyses(message_id integer,subject_kind text,result jsonb);
                INSERT INTO classifier_review_queue VALUES(1,2,'test','queued');
                INSERT INTO training_samples VALUES(2,3,'{"clues":[]}');
            """)
            view = {"version": "sentimail-visible-content-1", "source": "html_visible_text",
                    "text": "616 Consulter <script>", "truncated": False}
            await connection.execute("""INSERT INTO messages VALUES(3,'Objet','Expéditeur',
                'Bruit caché','<p>616 Consulter</p>',NULL,$1::jsonb)""", json.dumps({"visible_content": view}))
            query = sample_query(1)
            row = dict(await connection.fetchrow(query.sql, *query.params))
            text, incomplete = review_content(row)
            self.assertEqual(text, view["text"])
            self.assertFalse(incomplete)
            html = sample_page(row)
            self.assertNotIn("Bruit caché", html)
            self.assertNotIn('<script>', html)
            await connection.execute("UPDATE messages SET body_text=NULL,body_html=NULL,redacted_at=now()")
            row = dict(await connection.fetchrow(query.sql, *query.params))
            self.assertEqual(review_content(row), ("", True))
        finally:
            await connection.close()
