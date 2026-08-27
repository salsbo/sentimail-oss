from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

import asyncpg
from sentimail_v3.code import knowledge
from sentimail_v3.code.knowledge import lexical_query, load_directory, search, split_sections

RFC_LIKE = """





Network Working Group                                          A. Author
Request for Comments: 9999                                   Example Inc
Category: Standards Track                                   August 2026


                  Exemple de norme pour les tests


1.  Introduction

   Ce document decrit un protocole imaginaire dont le seul but est de
   verifier le decoupage. Il contient assez de texte pour depasser le
   seuil minimal impose aux sections, faute de quoi il serait ignore
   comme un simple titre sans contenu utile a la recherche.

Author                       Standards Track                    [Page 1]

RFC 9999                    Exemple de norme                 August 2026


2.  Alignement d'identifiant

   L'alignement compare le domaine de l'identite visible a celui de
   l'identite authentifiee. Sans alignement, une signature valide ne
   prouve rien sur l'expediteur affiche, ce qui est exactement le cas
   traite par cette section et par les suivantes du present document.

2.1.  Cas strict

   En mode strict, les domaines doivent etre identiques. Cette exigence
   supplementaire elimine les sous-domaines et rend la verification plus
   previsible pour un destinataire qui souhaite une regle simple et sans
   surprise lors de l'evaluation.

3.  Note

   Trop court.
"""


class SplitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chunks = split_sections(RFC_LIKE)
        self.titles = [title for title, _ in self.chunks]

    def test_sections_are_named_by_their_heading(self) -> None:
        self.assertIn("2. Alignement d'identifiant", self.titles)
        self.assertIn("2.1. Cas strict", self.titles)

    def test_a_section_too_short_to_teach_anything_is_dropped(self) -> None:
        self.assertNotIn("3. Note", self.titles)

    def test_page_furniture_never_reaches_the_text(self) -> None:
        for _, body in self.chunks:
            self.assertNotIn("[Page 1]", body)
            self.assertNotIn("Request for Comments:", body)
            self.assertNotIn("Category:", body)

    def test_bibliographies_and_registries_are_left_out(self) -> None:
        document = "\n\n".join(
            f"{numero}.  {titre}\n\n" + "Contenu de remplissage. " * 20
            for numero, titre in (
                (12, "References"),
                (13, "Normative References"),
                (14, "IANA Considerations"),
                (15, "Acknowledgements"),
                (16, "Authors' Addresses"),
            )
        )
        self.assertEqual(split_sections(document), [])

    def test_a_real_section_whose_title_mentions_references_is_kept(self) -> None:
        document = "4.1.4.  Identity References in a Message\n\n" + (
            "Une section qui parle vraiment des identifiants cites dans un "
            "message, et qu'il serait absurde d'ecarter au motif que son titre "
            "contient le mot references. " * 3
        )
        titres = [titre for titre, _ in split_sections(document)]
        self.assertEqual(titres, ["4.1.4. Identity References in a Message"])

    def test_long_sections_are_split_and_stay_bounded(self) -> None:
        long_document = "1.  Titre\n\n" + "\n\n".join(
            [f"Paragraphe numero {index} " + "texte " * 40 for index in range(20)]
        )
        chunks = split_sections(long_document)
        self.assertGreater(len(chunks), 1)
        for _, body in chunks:
            self.assertLessEqual(len(body), knowledge.MAX_CHUNK_CHARS)

    def test_a_block_without_a_single_blank_line_is_split_too(self) -> None:
        # Un sommaire de RFC : des dizaines de lignes, aucune ligne vide.
        sommaire = "1.  Titre\n\n" + "\n".join(
            f"   {index}. Une entree de sommaire assez longue pour compter"
            for index in range(200)
        )
        for _, body in split_sections(sommaire):
            self.assertLessEqual(len(body), knowledge.MAX_CHUNK_CHARS)


class QueryTests(unittest.TestCase):
    def test_the_question_keeps_only_what_discriminates(self) -> None:
        query = lexical_query("Comment est-ce que DMARC verifie l'alignement ?")
        self.assertIn("dmarc", query)
        self.assertIn("alignement", query)
        self.assertNotIn("comment", query)
        self.assertIn("|", query)

    def test_a_question_without_any_useful_word_asks_nothing(self) -> None:
        self.assertEqual(lexical_query("et le message ?"), "")
        self.assertEqual(lexical_query(""), "")


@unittest.skipUnless(os.environ.get("DATABASE_URL"), "DATABASE_URL absent")
class KnowledgeStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
        self.directory = Path(os.environ.get("TMPDIR", "/tmp")) / "knowledge-test"
        (self.directory / "snapshots").mkdir(parents=True, exist_ok=True)
        document = self.directory / "snapshots" / "rfc9999.txt"
        document.write_text(RFC_LIKE, encoding="utf-8")
        import hashlib

        digest = hashlib.sha256(document.read_bytes()).hexdigest()
        (self.directory / "manifest.json").write_text(
            json.dumps(
                {
                    "schema": "sentimail-v3-knowledge-manifest-1",
                    "nature": "normative",
                    "documents": [
                        {
                            "id": "rfc9999",
                            "title": "RFC 9999 - Exemple",
                            "url": "https://example.invalid/rfc9999",
                            "topic": "authentification",
                            "path": "snapshots/rfc9999.txt",
                            "sha256": digest,
                            "captured_on": "2026-08-13",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    async def asyncTearDown(self) -> None:
        await self.pool.execute(
            "DELETE FROM knowledge_documents WHERE source_id='rfc9999'"
        )
        await self.pool.close()

    async def test_loading_is_idempotent(self) -> None:
        first = await load_directory(self.pool, self.directory)
        self.assertEqual(first["documents_loaded"], 1)
        self.assertGreater(first["passages"], 1)
        second = await load_directory(self.pool, self.directory)
        self.assertEqual(second["documents_loaded"], 0)
        self.assertEqual(second["documents_unchanged"], 1)

    async def test_changing_the_embedding_model_revectorises(self) -> None:
        async with self._embedder() as client:
            first = await load_directory(
                self.pool,
                self.directory,
                client=client,
                base_url="http://embed.invalid",
                model="jouet",
            )
            self.assertEqual(first["documents_loaded"], 1)
            self.assertEqual(first["passages_without_vector"], 0)
            # Même contenu, autre modèle : les vecteurs d'avant ne sont plus
            # comparables, le document doit repasser.
            again = await load_directory(
                self.pool,
                self.directory,
                client=client,
                base_url="http://embed.invalid",
                model="jouet-2",
            )
        self.assertEqual(again["documents_loaded"], 1)
        self.assertEqual(again["documents_unchanged"], 0)
        model = await self.pool.fetchval(
            """
            SELECT DISTINCT c.embedding_model FROM knowledge_chunks c
            JOIN knowledge_documents d ON d.id=c.document_id
            WHERE d.source_id='rfc9999'
            """
        )
        self.assertEqual(model, "jouet-2")

    async def test_a_tampered_snapshot_is_refused(self) -> None:
        (self.directory / "snapshots" / "rfc9999.txt").write_text(
            RFC_LIKE + "\n\nAjout non signé.", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "empreinte"):
            await load_directory(self.pool, self.directory)

    async def test_a_question_finds_the_right_section(self) -> None:
        await load_directory(self.pool, self.directory)
        passages = await search(self.pool, "alignement strict des domaines")
        self.assertTrue(passages)
        self.assertEqual(passages[0].source_id, "rfc9999")
        found = " ".join(f"{item.section} {item.body}" for item in passages)
        self.assertIn("strict", found.lower())
        self.assertIn("align", found.lower())

    async def test_an_unrelated_question_returns_nothing(self) -> None:
        await load_directory(self.pool, self.directory)
        self.assertEqual(
            await search(self.pool, "recette de tarte aux pommes bretonne"), []
        )

    @staticmethod
    def _embedder() -> "httpx.AsyncClient":
        import json as _json

        import httpx

        # Un embeddeur jouet, mais déterministe : chaque dimension compte un
        # mot du corpus. Suffisant pour éprouver le chemin, pas le modèle.
        axes = ("align", "strict", "domain", "protocole", "decoupage", "identite")

        async def handler(request: httpx.Request) -> httpx.Response:
            text = _json.loads(request.content)["prompt"].lower()
            return httpx.Response(
                200, json={"embedding": [float(text.count(axe)) for axe in axes]}
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def test_a_question_without_a_single_shared_word_still_finds_its_answer(
        self,
    ) -> None:
        async with self._embedder() as client:
            await load_directory(
                self.pool,
                self.directory,
                client=client,
                base_url="http://embed.invalid",
                model="jouet",
            )
            # Aucun de ces mots n'est dans le texte : seul le sens peut relier.
            passages = await search(
                self.pool,
                "identite alignee",
                client=client,
                base_url="http://embed.invalid",
                model="jouet",
            )
        self.assertTrue(passages)
        self.assertIn("align", " ".join(item.body for item in passages).lower())

    async def test_a_semantic_sweep_admits_when_nothing_is_close(self) -> None:
        async with self._embedder() as client:
            await load_directory(
                self.pool,
                self.directory,
                client=client,
                base_url="http://embed.invalid",
                model="jouet",
            )
            passages = await search(
                self.pool,
                "tarte tatin caramel beurre",
                client=client,
                base_url="http://embed.invalid",
                model="jouet",
            )
        self.assertEqual(passages, [])

    async def test_search_survives_an_embedding_outage(self) -> None:
        await load_directory(self.pool, self.directory)
        import httpx

        async def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("ollama absent", request=request)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(refuse)
        ) as broken:
            passages = await search(
                self.pool,
                "alignement strict des domaines",
                client=broken,
                base_url="http://ollama.invalid",
                model="nomic-embed-text",
            )
        # L'ordre lexical suffit : la connaissance ne disparaît pas avec Ollama.
        self.assertTrue(passages)


if __name__ == "__main__":
    unittest.main()
