-- Deux tables demandées le 20/08 au soir.
--
-- participant_preferences : les réglages propres à un destinataire, en
-- clé/valeur - le premier est l'accusé de réception des directives
-- (directive_receipt_enabled), activable et désactivable par email.
--
-- hostile_smtp_sources : la réputation interne des serveurs SMTP ayant livré
-- du spam confirmé (verdict indésirable ou qualification humaine). La
-- rétention purge les messages ; la trace de la source demeure. Consultable
-- comme cache, exploitable plus tard pour un blocage au niveau de Postfix.

CREATE TABLE IF NOT EXISTS participant_preferences (
    participant_email text NOT NULL,
    name text NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (participant_email, name)
);

CREATE TABLE IF NOT EXISTS hostile_smtp_sources (
    ip inet PRIMARY KEY,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    hits integer NOT NULL DEFAULT 1,
    last_reason text NOT NULL
);

CREATE INDEX IF NOT EXISTS hostile_smtp_sources_last_seen_idx
    ON hostile_smtp_sources (last_seen DESC);
