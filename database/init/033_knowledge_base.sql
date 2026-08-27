-- La connaissance normative de la messagerie : RFC et spécifications figées.
--
-- Elle est publique, stable et citable, et c'est tout ce qu'elle est. Elle
-- n'appartient à aucun destinataire, ne contient aucune donnée personnelle et
-- n'entre donc pas dans la rétention. Surtout, elle explique : elle ne prouve
-- rien sur un message et ne peut jamais créer un indice ni lever une barrière.

CREATE TABLE IF NOT EXISTS knowledge_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id text NOT NULL UNIQUE,
    title text NOT NULL,
    url text NOT NULL,
    topic text NOT NULL,
    nature text NOT NULL DEFAULT 'normative'
        CHECK (nature IN ('normative', 'internal')),
    sha256 text NOT NULL,
    captured_on date NOT NULL,
    loaded_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE knowledge_documents IS
    'Sources figées dans le dépôt. Le sha256 est celui du snapshot versionné : '
    'une réponse citant un document reste réexplicable des mois plus tard.';

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id bigserial PRIMARY KEY,
    document_id uuid NOT NULL
        REFERENCES knowledge_documents(id) ON DELETE CASCADE,
    ordinal int NOT NULL,
    section text NOT NULL,
    body text NOT NULL,
    -- 'simple' et non 'french' ou 'english' : ces documents sont en anglais,
    -- les questions arrivent en français, et les termes qui comptent (DMARC,
    -- SPF, alignment) ne se dérivent dans aucune des deux langues.
    search tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', section || ' ' || body)
    ) STORED,
    embedding bytea,
    embedding_model text,
    UNIQUE (document_id, ordinal)
);

CREATE INDEX IF NOT EXISTS knowledge_chunks_search_idx
    ON knowledge_chunks USING gin (search);

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'knowledge.base_created',
    '{"version":"1.0.0","nature":"normative","retrieval":"lexical_then_semantic","never":"evidence"}'
);
