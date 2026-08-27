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
    ('CONTENT-008','Expiration intrinsèque à un usage unique',
     'L’expiration rapide d’un lien ou code à usage unique est cohérente avec sa fonction de sécurité et ne constitue pas seule une pression frauduleuse.',
     'neutral',0,'info','L’identité, la destination et la nature exacte de l’action restent à vérifier.','{"context_kind":"intrinsic_expiration"}'),
    ('CONTENT-009','Secret fourni sans demande de divulgation',
     'Un message qui fournit un code ou un lien à usage unique sans demander de révéler un secret présente un contexte différent d’une collecte d’identifiants.',
     'favorable',18,'info','Un expéditeur ou une destination compromis restent possibles ; ce signal n’est jamais décisif seul.','{"context_kind":"one_time_authentication"}'),
    ('CONTENT-010','Utilisation attendue d’un code à usage unique',
     'Demander de saisir un code dans son parcours d’authentification diffère d’une demande de communiquer ce code à un tiers.',
     'neutral',0,'info','Une demande de réponse, d’envoi ou de partage du code reste une demande sensible à charge.','{"context_kind":"expected_one_time_input"}'),
    ('DEEP-013','URL à effet de bord protégée',
     'Une URL susceptible d’être à usage unique ou de déclencher une action ne doit faire l’objet d’aucune requête HTTP ; seule son analyse statique est permise.',
     'neutral',0,'info','L’absence volontaire de navigation ne rend pas l’analyse incomplète ; les autres preuves du message restent nécessaires.','{"network_navigation_forbidden":true}'),
    ('DEEP-014','Formulaire sensible ambiant non corrélé',
     'La présence d’un formulaire sensible sur une page distante ne prouve pas que l’email demande cette donnée lorsque le lien et le contexte du message ne corroborent pas cette collecte.',
     'neutral',0,'info','Une destination trompeuse, non authentifiée ou malveillante peut requalifier ce fait sous DEEP-002.','{"requires_context_correlation":true}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

UPDATE code_articles SET
    title='Formulaire sensible dans un contexte trompeur corrélé',
    principle='Un formulaire demandant une donnée sensible devient une charge forte seulement si la demande du message et une destination non authentifiée, redirigée ou trompeuse se corroborent.',
    limitations='La catégorie de donnée doit être nommée. Un formulaire de connexion ambiant sur un site externe, sans demande corrélée de l’email, relève de DEEP-014.'
WHERE article_code='DEEP-002';

UPDATE code_articles SET
    principle='Une pression temporelle devient suspecte selon sa nature et son contexte : une contrainte coercitive financière diffère d’une expiration intrinsèque à un code à usage unique.',
    limitations='Le type d’urgence, la finalité du message, l’action demandée et les données effectivement demandées doivent être explicités.'
WHERE article_code='CONTENT-001';

UPDATE code_articles SET
    principle='Seule une demande explicite de divulgation ou de saisie d’une catégorie sensible constitue cet indice ; la simple mention d’un code, d’une connexion ou d’un paiement ne suffit pas.',
    limitations='La catégorie exacte et le verbe de demande doivent être conservés dans les faits.'
WHERE article_code='CONTENT-002';

UPDATE code_articles SET
    title='Limite de navigation authentifiée et contextualisée',
    principle='Une boucle HTTPS stabilisée ou une panne de dialogue HTTP confinée au même apex authentifié constitue une limite technique expliquée, pas une preuve de danger.',
    limitations='Un changement d’apex non expliqué, une destination non authentifiée ou l’absence de destination observable reste une analyse incomplète.'
WHERE article_code='DEEP-012';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.contextual_evidence_enabled',
    '{"version":"0.6.0","principle":"urgency_action_and_sensitive_data_require_context"}'
);
