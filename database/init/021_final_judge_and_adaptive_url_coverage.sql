UPDATE code_articles
SET limitations = replace(
        limitations,
        ' Cette qualification est une barrière de livraison explicite même si le LLM conclut légitime.',
        ' Cette qualification matérielle est soumise au juge comme règle de droit avant son verdict final.'
    )
WHERE article_code IN ('ATT-001','ATT-002','RSPAMD-002','DEEP-004');

UPDATE code_articles
SET limitations =
        'Seul un échec réel sur une URL représentative constitue une incomplétude. '
        'Un plafond d’échantillonnage ou des variantes regroupées sont décrits au juge '
        'comme couverture limitée et ne forcent jamais seuls une retenue.'
WHERE article_code='DEEP-003';

UPDATE code_articles
SET limitations =
        'La réduction de seuil exige DMARC=pass. L’autorisation, les preuves '
        'matérielles, les limites réelles et le contexte sont tous soumis au juge '
        'avant son verdict final ; aucun veto distinct ne repasse après lui.'
WHERE article_code='POLICY-002';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.final_judge_and_adaptive_url_coverage_enabled',
    '{"version":"1.0.0","judge_is_final":true,"post_judgment_veto":false,"url_strategy":"adaptive-contextual-representatives-v1","url_budget":{"base":20,"hard_max":40}}'
);
