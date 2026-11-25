"""Les jetons des anciens pieds de page sont révoqués, pas ceux des avis.

Le pied de page des messages livrés a disparu le 14 septembre 2026. Ses jetons
restaient valables 180 jours, et trois circulaient déjà chez un tiers dans un
fil cité. Les boutons A des avis d'indésirable, eux, sont le seul geste de ces
avis : ils restent.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "init"
    / "093_jetons_pied_de_page_revoques.sql"
)


def _sql() -> str:
    texte = MIGRATION.read_text(encoding="utf-8")
    # Les commentaires racontent le pourquoi ; seul le code agit.
    return "\n".join(line.split("--", 1)[0] for line in texte.splitlines())


class MigrationTests(unittest.TestCase):
    def test_la_migration_ne_revoque_que_les_pieds_de_page(self) -> None:
        sql = _sql()
        self.assertIn("SET status = 'revoked'", sql)
        self.assertIn("sa.status = 'pending'", sql)
        self.assertIn("'delivered_feedback'", sql)
        self.assertIn("NOT EXISTS", sql)
        self.assertIn("'original_filed_as_junk'", sql)
        self.assertIn("sa.issued_at < '2026-09-14 14:05:00+00'", sql)
        self.assertNotRegex(sql, re.compile(r"\bDELETE\b", re.IGNORECASE))

    def test_l_audit_garde_les_identifiants_pour_le_retour_arriere(self) -> None:
        sql = _sql()
        self.assertIn("'smtp_actions.footer_tokens_revoked'", sql)
        self.assertIn("'ids'", sql)
        # Sur une base neuve, rien n'est révoqué : la liste doit rester un
        # tableau, sinon le retour arrière documenté échoue sur un null.
        self.assertIn("coalesce(jsonb_agg(id), '[]'::jsonb)", sql)

    def test_le_texte_est_en_utf8_sans_tiret_cadratin(self) -> None:
        texte = MIGRATION.read_text(encoding="utf-8")
        self.assertNotIn("—", texte)
        self.assertIn("révoqués", texte)


if __name__ == "__main__":
    unittest.main()
