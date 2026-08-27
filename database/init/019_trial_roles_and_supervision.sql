WITH editions AS (
    SELECT id FROM code_editions
    WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT editions.id, article_code, title, principle, direction, strength,
       severity, limitations, parameters::jsonb
FROM editions
CROSS JOIN (VALUES
    ('DOMAIN-002','Domaine expéditeur établi',
     'Un domaine ancien constitue un indice contextuel favorable limité contre un domaine jetable récemment créé.',
     'favorable',15,'info','Un domaine ancien peut être compromis, revendu ou utilisé pour diffuser du spam ; cet indice n’est jamais décisif seul.','{"evidence_family":"domain_history"}'),
    ('DOMAIN-003','Âge du domaine indisponible',
     'L’impossibilité d’établir la date de création du domaine est une limite de contexte et non une preuve de fraude.',
     'neutral',0,'info','Le superviseur opérationnel doit signaler les échecs d’enrichissement répétés.','{"evidence_kind":"technical_limit"}'),
    ('IDENTITY-006','Homographe Unicode dans l’identité',
     'Un mélange de scripts visuellement proches ou un libellé IDNA dans l’identité de l’expéditeur peut masquer une identité différente.',
     'adverse',75,'high','Le caractère exact et son point de code doivent être conservés ; un nom internationalisé légitime reste possible.','{"evidence_family":"identity_deception"}'),
    ('IDENTITY-007','Caractères ASCII visuellement ambigus',
     'Les substitutions 0/o, 1/l ou I/l dans une identité sont relevées pour comparaison avec le contexte et la marque revendiquée.',
     'neutral',0,'info','Sans identité de référence ou autre tromperie, une ressemblance ASCII ne constitue pas une charge.','{"evidence_family":"identity_deception"}'),
    ('IDENTITY-008','Domaine internationalisé à contextualiser',
     'La présence d’un libellé IDNA est observée sans l’assimiler automatiquement à une homographie.',
     'neutral',0,'info','Seul un mélange de scripts ou une comparaison avec une identité de référence peut transformer ce contexte en charge.','{"evidence_family":"identity_deception"}'),
    ('RSPAMD-008','Aucun signal de réputation défavorable observé',
     'L’absence de symbole de liste de réputation défavorable dans le résultat Rspamd constitue un indice favorable faible.',
     'favorable',5,'info','L’absence de signal ne prouve pas une bonne réputation et dépend des sources effectivement consultées par Rspamd.','{"evidence_family":"external_reputation"}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.trial_roles_identity_and_supervision_enabled',
    '{"version":"0.8.0","verdict_roles":["prosecutor","defence","judge"],"supervisor":"deterministic_no_silent_soft_fail","new_evidence":["domain_age","rspamd_reputation","unicode_homograph","ascii_lookalike","idn_context"]}'
);
