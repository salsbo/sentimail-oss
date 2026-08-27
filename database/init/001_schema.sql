CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ingest_key text NOT NULL UNIQUE,
    captured_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    delivery_status text NOT NULL DEFAULT 'captured'
        CHECK (delivery_status IN ('captured', 'deferred', 'delivered')),
    delivery_attempts integer NOT NULL DEFAULT 0,
    last_delivery_error text,

    smtp_peer_ip inet,
    smtp_peer_port integer,
    smtp_helo text,
    smtp_protocol text,
    smtp_tls jsonb NOT NULL DEFAULT '{}'::jsonb,
    smtp_authenticated boolean,
    envelope_from text NOT NULL,
    envelope_recipients text[] NOT NULL,
    smtp_mail_options text[] NOT NULL DEFAULT '{}',
    smtp_rcpt_options jsonb NOT NULL DEFAULT '{}'::jsonb,

    raw_eml bytea NOT NULL,
    raw_sha256 char(64) NOT NULL,
    raw_size_bytes bigint NOT NULL,
    headers_size_bytes bigint NOT NULL,
    body_size_bytes bigint NOT NULL,
    line_count integer NOT NULL,
    max_line_length integer NOT NULL,
    contains_8bit boolean NOT NULL,
    contains_nul boolean NOT NULL,
    line_ending text NOT NULL,

    message_id text,
    subject text,
    from_header text,
    to_header text,
    cc_header text,
    reply_to_header text,
    return_path_header text,
    header_date_raw text,
    header_date timestamptz,
    header_date_parse_error text,
    mime_version text,
    root_content_type text NOT NULL,
    root_charset text,
    root_transfer_encoding text,
    body_text text,
    body_html text,
    parser_version text NOT NULL,
    parser_defects jsonb NOT NULL DEFAULT '[]'::jsonb,
    facts jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_messages_captured_at ON messages (captured_at DESC);
CREATE INDEX ix_messages_header_date ON messages (header_date DESC);
CREATE INDEX ix_messages_envelope_from ON messages (lower(envelope_from));
CREATE INDEX ix_messages_raw_sha256 ON messages (raw_sha256);
CREATE INDEX ix_messages_facts_gin ON messages USING gin (facts);

CREATE TABLE headers (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    ordinal integer NOT NULL,
    name_original text NOT NULL,
    name_normalized text NOT NULL,
    value_raw text NOT NULL,
    value_decoded text NOT NULL,
    value_sha256 char(64) NOT NULL,
    value_length integer NOT NULL,
    is_trace boolean NOT NULL DEFAULT false,
    is_security boolean NOT NULL DEFAULT false,
    UNIQUE (message_id, ordinal)
);

CREATE INDEX ix_headers_name ON headers (name_normalized);
CREATE INDEX ix_headers_message_name ON headers (message_id, name_normalized);

CREATE TABLE mime_parts (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    path text NOT NULL,
    parent_path text,
    ordinal integer NOT NULL,
    is_multipart boolean NOT NULL,
    is_attachment boolean NOT NULL,
    content_type text NOT NULL,
    maintype text NOT NULL,
    subtype text NOT NULL,
    charset text,
    content_transfer_encoding text,
    content_disposition text,
    filename text,
    content_id text,
    content_description text,
    content_language text,
    content_location text,
    decoded_size_bytes bigint NOT NULL,
    decoded_sha256 char(64),
    text_content text,
    parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    defects jsonb NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (message_id, path)
);

CREATE INDEX ix_mime_parts_type ON mime_parts (content_type);
CREATE INDEX ix_mime_parts_attachments ON mime_parts (message_id) WHERE is_attachment;

CREATE TABLE entities (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    entity_type text NOT NULL
        CHECK (entity_type IN ('address', 'domain', 'ip', 'url', 'message_id', 'hash')),
    role text NOT NULL,
    ordinal integer NOT NULL,
    value_raw text NOT NULL,
    value_normalized text NOT NULL,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    enrichment_id bigint,
    UNIQUE (message_id, entity_type, role, ordinal)
);

CREATE INDEX ix_entities_lookup ON entities (entity_type, value_normalized);
CREATE INDEX ix_entities_message ON entities (message_id, entity_type);

CREATE TABLE enrichments (
    id bigserial PRIMARY KEY,
    entity_type text NOT NULL CHECK (entity_type IN ('domain', 'ip')),
    value_normalized text NOT NULL,
    source text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('ok', 'not_found', 'error')),
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text
);

ALTER TABLE entities
    ADD CONSTRAINT fk_entities_enrichment
    FOREIGN KEY (enrichment_id) REFERENCES enrichments(id) ON DELETE SET NULL;

CREATE INDEX ix_enrichments_lookup
    ON enrichments (entity_type, value_normalized, observed_at DESC);

CREATE TABLE features (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    namespace text NOT NULL,
    name text NOT NULL,
    extractor text NOT NULL,
    extractor_version text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    value_text text,
    value_number double precision,
    value_boolean boolean,
    value_json jsonb,
    confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    provenance jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_features_name ON features (namespace, name);
CREATE INDEX ix_features_message ON features (message_id);

CREATE TABLE labels (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    source text NOT NULL,
    label text NOT NULL,
    confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    is_ground_truth boolean NOT NULL DEFAULT false,
    model_name text,
    model_version text,
    context jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_labels_training ON labels (is_ground_truth, label);

CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    actor text NOT NULL,
    action text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
