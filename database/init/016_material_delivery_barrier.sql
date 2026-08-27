UPDATE code_articles
SET parameters = parameters || jsonb_build_object(
        'delivery_barrier', 'material_danger',
        'material_kind', CASE article_code
            WHEN 'RSPAMD-002' THEN 'malware_or_virus'
            WHEN 'DEEP-004' THEN 'sandbox_confirmed_active_or_malicious_file'
            ELSE 'executable_attachment'
        END
    ),
    limitations = limitations ||
        ' Cette qualification est une barrière de livraison explicite même si le LLM conclut légitime.'
WHERE article_code IN ('ATT-001','ATT-002','RSPAMD-002','DEEP-004');

UPDATE code_articles
SET parameters = parameters - 'delivery_barrier' - 'material_kind'
WHERE article_code NOT IN ('ATT-001','ATT-002','RSPAMD-002','DEEP-004');

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'policy.material_delivery_barrier_enabled',
    '{"version":"0.5.0","invariant":"legitimate_and_confident_and_complete_and_no_material_danger_delivers","material_articles":["ATT-001","ATT-002","RSPAMD-002","DEEP-004"],"heuristic_scores_never_veto":true}'
);
