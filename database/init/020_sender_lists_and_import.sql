ALTER TABLE sender_policies DROP CONSTRAINT sender_policies_action_check;
ALTER TABLE sender_policies ADD CONSTRAINT sender_policies_action_check
    CHECK (action IN ('hold','allow'));

ALTER TABLE assistant_interpretations
    DROP CONSTRAINT assistant_interpretations_requested_action_check;
ALTER TABLE assistant_interpretations
    ADD CONSTRAINT assistant_interpretations_requested_action_check CHECK (
        requested_action IS NULL OR requested_action IN (
            'release_original', 'suppress_future', 'cancel_suppression',
            'record_feedback', 'explain', 'list_rules', 'import_rules',
            'set_sender_rule',
            'update_rule', 'disable_rule', 'restore_rule', 'none'
        )
    );

WITH editions AS (
    SELECT id FROM code_editions
    WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT editions.id, 'POLICY-002', 'Expéditeur explicitement autorisé',
       'Une décision SMTP authentifiée de l’utilisateur constitue un indice favorable pour cet expéditeur exact.',
       'favorable', 25, 'info',
       'La réduction de seuil exige aussi DMARC=pass. Cette autorisation ne contourne jamais une analyse incomplète, une preuve matérielle de danger ou le jugement contextuel du message.',
       '{"evidence_family":"authenticated_user_policy","scope":"exact_sender"}'::jsonb
FROM editions
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'sender_lists.smtp_management_enabled',
    '{"version":"0.9.0","lists":["allow","hold"],"import":["csv","txt"],"allow_bypass_material_danger":false}'
);
