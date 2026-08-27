-- Ce qu'une recherche a rendu, gardé pour ne pas le redemander.
--
-- Mesuré sur sept jours de courrier réel : 311 messages appellent une
-- confrontation nom/domaine, mais ils ne portent que 115 noms et 96 domaines
-- distincts. Sans mémoire, 622 recherches partent là où 211 suffisent - et le
-- même expéditeur serait redemandé chaque matin.
--
-- La table garde les extraits eux-mêmes, pas seulement les domaines déduits :
-- c'est ce que le modèle lit pour juger, et le relire n'a pas à coûter une
-- nouvelle recherche.
CREATE TABLE IF NOT EXISTS search_lookups (
    query_key text PRIMARY KEY,
    kind text NOT NULL,
    results jsonb NOT NULL DEFAULT '[]'::jsonb,
    apexes text[] NOT NULL DEFAULT '{}',
    checked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_search_lookups_checked ON search_lookups (checked_at);

COMMENT ON TABLE search_lookups IS
  'Résultats de recherche gardés par question posée ; mémoire, jamais une décision.';
