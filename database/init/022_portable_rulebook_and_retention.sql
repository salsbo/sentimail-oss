-- Le registre d'apprentissage devient autoportant et la base reçoit une
-- fenêtre de rétention. Un label garde l'identité du correspondant, le
-- destinataire et l'objet témoin : il survit donc au dégonflage puis à la
-- suppression du message d'origine. Seules les directives et les règles
-- restent tracées sans limite de durée.

ALTER TABLE labels ADD COLUMN IF NOT EXISTS sender_normalized text;
ALTER TABLE labels ADD COLUMN IF NOT EXISTS participant_email text;
ALTER TABLE labels ADD COLUMN IF NOT EXISTS subject text;

ALTER TABLE labels ALTER COLUMN message_id DROP NOT NULL;
ALTER TABLE labels DROP CONSTRAINT IF EXISTS labels_message_id_fkey;
ALTER TABLE labels
    ADD CONSTRAINT labels_message_id_fkey
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL;

-- Reprise des labels déjà enregistrés : adresse visible du From si elle est
-- exploitable, sinon enveloppe SMTP ; destinataire réel de la conversation
-- quand il existe, sinon premier destinataire d'enveloppe.
UPDATE labels l
SET sender_normalized = lower(
        coalesce(
            nullif(substring(m.from_header from '<([^>]+)>'), ''),
            nullif(btrim(coalesce(m.from_header, '')), ''),
            m.envelope_from
        )
    ),
    participant_email = lower(
        coalesce(
            (
                SELECT c.participant_email
                FROM delivery_cases dc
                JOIN conversations c ON c.case_id = dc.id
                WHERE dc.message_id = m.id
                ORDER BY c.created_at DESC
                LIMIT 1
            ),
            m.envelope_recipients[1]
        )
    ),
    subject = m.subject
FROM messages m
WHERE m.id = l.message_id AND l.sender_normalized IS NULL;

CREATE INDEX IF NOT EXISTS ix_labels_sender_participant
    ON labels (sender_normalized, participant_email)
    WHERE is_ground_truth = true AND active = true;

-- Rétention : le contenu redevient effaçable sans perdre la trace de la
-- décision, de la directive ni des indices.
ALTER TABLE messages ALTER COLUMN raw_eml DROP NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS redacted_at timestamptz;
CREATE INDEX IF NOT EXISTS ix_messages_retention
    ON messages (captured_at) WHERE redacted_at IS NULL;

ALTER TABLE conversation_messages ALTER COLUMN body_text DROP NOT NULL;

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration',
    'retention.portable_rulebook_and_windows_enabled',
    '{"rulebook_survives_purge":true,"redact_after_days":30,"delete_after_days":180,"kept_forever":["labels","sender_policies","assistant_interpretations","audit_log"]}'
);
