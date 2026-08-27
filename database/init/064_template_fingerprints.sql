-- Empreintes de gabarit des campagnes (recherche 20/08 : reconnaitre "le meme
-- message" a travers expediteurs/destinataires differents, en local pur).
--
-- template_fingerprints : le squelette MinHash d'un message qualifie + son
-- sujet masque + le label de la campagne.
-- template_lsh_buckets : l'index LSH par bandes ; deux squelettes proches
-- partagent au moins une band_key, ce qui evite de comparer a toute la base.

CREATE TABLE IF NOT EXISTS template_fingerprints (
    id               bigserial PRIMARY KEY,
    message_id       uuid,
    label            text NOT NULL,
    signature        integer[] NOT NULL,
    subject_template text,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS template_lsh_buckets (
    band_key       text NOT NULL,
    fingerprint_id bigint NOT NULL REFERENCES template_fingerprints(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS template_lsh_buckets_key_idx
    ON template_lsh_buckets (band_key);
CREATE INDEX IF NOT EXISTS template_fingerprints_created_idx
    ON template_fingerprints (created_at DESC);
