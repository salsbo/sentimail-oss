ALTER TABLE smtp_actions DROP CONSTRAINT smtp_actions_action_check;
ALTER TABLE smtp_actions ADD CONSTRAINT smtp_actions_action_check CHECK (action IN (
    'give_directive', 'report_spam', 'release_original', 'mark_legitimate',
    'suppress_future', 'cancel_suppression', 'credential_upload',
    'credential_password'
));

CREATE TABLE llm_provider_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    provider text NOT NULL CHECK (provider IN ('deepseek','anthropic','openai')),
    model_name text NOT NULL,
    secret_filename text NOT NULL CHECK (
        secret_filename IN ('deepseek_api_key','anthropic_api_key','openai_api_key')
    ),
    validated_at timestamptz NOT NULL,
    configured_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE llm_provider_setup_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    participant_email text NOT NULL,
    provider text NOT NULL CHECK (provider IN ('deepseek','anthropic','openai')),
    model_name text NOT NULL,
    state text NOT NULL CHECK (
        state IN ('awaiting_zip','awaiting_password','validating','complete','failed','expired')
    ),
    encrypted_zip bytea,
    encrypted_zip_sha256 char(64),
    failed_attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_llm_provider_setup_active
    ON llm_provider_setup_sessions (state, expires_at)
    WHERE state IN ('awaiting_zip','awaiting_password','validating');

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'llm_provider.smtp_setup_enabled',
    '{"version":"0.1.0","secret_in_database":false,"llm_sees_secret":false,"two_message_exchange":true}'
);
