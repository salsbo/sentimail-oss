UPDATE code_articles SET
    title='Limite technique d’inspection URL',
    principle='Une URL que le sandbox ne peut pas inspecter complètement constitue une limite procédurale et jamais une preuve à charge.',
    default_direction='neutral',
    default_strength=0,
    severity='info',
    limitations='La politique peut demander une revue si aucune variante équivalente et même-apex n’apporte une couverture suffisante.',
    parameters=coalesce(parameters, '{}'::jsonb) || '{"forces_doubt":true,"evidence_kind":"technical_limit"}'::jsonb
WHERE article_code='DEEP-003';

UPDATE code_articles SET
    title='Limite technique d’inspection fichier',
    principle='Un fichier que le sandbox ne peut pas inspecter complètement constitue une limite procédurale et jamais une preuve à charge.',
    default_direction='neutral',
    default_strength=0,
    severity='info',
    limitations='Le fichier, sa référence et la cause technique doivent être nommés ; une analyse matériellement incomplète peut encore imposer une revue.',
    parameters=coalesce(parameters, '{}'::jsonb) || '{"forces_doubt":true,"evidence_kind":"technical_limit"}'::jsonb
WHERE article_code='DEEP-005';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.technical_limits_neutralized',
    '{"version":"0.7.0","principles":["sandbox_error_is_not_adverse","named_technical_limits","postgres_json_nul_sanitized"]}'
);
