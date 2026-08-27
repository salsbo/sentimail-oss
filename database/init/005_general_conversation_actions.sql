ALTER TABLE smtp_actions ALTER COLUMN case_id DROP NOT NULL;

INSERT INTO audit_log (actor, action, payload)
VALUES (
    'migration', 'smtp_conversation.general_threading_enabled',
    '{"version":"0.1.0","transport":"smtp","binding":false}'
);
