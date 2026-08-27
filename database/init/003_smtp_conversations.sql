ALTER TABLE messages DROP CONSTRAINT messages_delivery_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_delivery_status_check
    CHECK (delivery_status IN ('captured', 'deferred', 'delivered', 'consumed'));
ALTER TABLE smtp_actions ALTER COLUMN token_hash DROP NOT NULL;
ALTER TABLE smtp_actions DROP CONSTRAINT smtp_actions_action_check;
ALTER TABLE smtp_actions ADD CONSTRAINT smtp_actions_action_check CHECK (action IN (
    'give_directive', 'report_spam', 'release_original', 'mark_legitimate',
    'suppress_future', 'cancel_suppression'
));

CREATE TABLE conversations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid REFERENCES delivery_cases(id) ON DELETE SET NULL,
    participant_email text NOT NULL,
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'awaiting_user', 'processing', 'closed', 'error')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_conversations_case ON conversations (case_id);
CREATE UNIQUE INDEX ux_conversations_case
    ON conversations (case_id) WHERE case_id IS NOT NULL;

CREATE TABLE conversation_messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    direction text NOT NULL CHECK (direction IN ('inbound', 'outbound', 'system')),
    message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
    internet_message_id text,
    subject text,
    body_text text NOT NULL,
    user_text text,
    processing_status text NOT NULL DEFAULT 'complete'
        CHECK (processing_status IN ('pending', 'processing', 'complete', 'error')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_conversation_messages_pending
    ON conversation_messages (processing_status, created_at)
    WHERE direction = 'inbound';

CREATE TABLE assistant_interpretations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_message_id uuid NOT NULL
        REFERENCES conversation_messages(id) ON DELETE CASCADE,
    model_name text NOT NULL,
    prompt_version text NOT NULL,
    intent text NOT NULL,
    classification text CHECK (
        classification IS NULL OR classification IN (
            'legitimate', 'spam', 'dangerous', 'suspect', 'undetermined'
        )
    ),
    requested_action text CHECK (
        requested_action IS NULL OR requested_action IN (
            'release_original', 'suppress_future', 'cancel_suppression',
            'record_feedback', 'explain', 'none'
        )
    ),
    scope text CHECK (
        scope IS NULL OR scope IN ('this_message', 'sender', 'domain', 'future', 'unknown')
    ),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    explanation text NOT NULL,
    clarification_question text,
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    raw_response jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'proposed'
        CHECK (status IN ('proposed', 'confirmed', 'corrected', 'rejected', 'error')),
    binding boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assistant_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    action_id uuid REFERENCES smtp_actions(id) ON DELETE SET NULL,
    recipient text NOT NULL,
    sender text NOT NULL,
    reply_to text NOT NULL,
    subject text NOT NULL,
    body_text text NOT NULL,
    internet_message_id text UNIQUE,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'error')),
    attempts integer NOT NULL DEFAULT 0,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

CREATE INDEX ix_assistant_outbox_pending
    ON assistant_outbox (status, created_at) WHERE status IN ('pending', 'error');

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'smtp_conversation.enabled',
    '{"version":"0.1.0","binding":false,"llm_role":"interpretation_only"}'
);
