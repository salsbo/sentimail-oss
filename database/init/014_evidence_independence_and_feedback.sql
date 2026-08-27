WITH editions AS (
    SELECT id FROM code_editions WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT editions.id, article_code, title, principle, direction, strength,
       severity, limitations, parameters::jsonb
FROM editions
CROSS JOIN (VALUES
    ('RSPAMD-006','Réputation externe Rspamd',
     'Une liste de réputation défavorable constitue une charge à corroborer avec la date, la cible et les autres familles de preuve.',
     'adverse',55,'medium','Une réputation peut être obsolète, mutualisée ou contextuelle ; elle ne prouve pas seule une intention malveillante.','{}'),
    ('RSPAMD-007','Hypothèse de phishing Rspamd',
     'Un symbole heuristique PHISHING est une allégation à vérifier avec le lien affiché, la chaîne de redirection et la destination finale.',
     'neutral',0,'info','Le symbole et le score agrégé qui le contient ne sont pas deux preuves indépendantes.','{}'),
    ('DEEP-009','Convergence du domaine présenté',
     'Le domaine présenté à l’utilisateur et la destination finale convergent après le lien intermédiaire.',
     'favorable',25,'info','Cette convergence réfute la tromperie du libellé mais ne garantit pas à elle seule tout le contenu distant.','{}'),
    ('DEEP-010','Divergence finale non authentifiée',
     'Un expéditeur non authentifié présente un domaine qui reste différent de la destination finale vérifiée.',
     'adverse',65,'high','Le contexte du lien et une éventuelle destination légitime externe doivent encore être examinés.','{}'),
    ('DEEP-011','Divergence finale authentifiée à expliquer',
     'Chez un expéditeur authentifié, une divergence entre domaine présenté et destination finale reste un point contesté à expliquer.',
     'neutral',0,'info','Les boutiques d’applications, réseaux sociaux et prestataires légitimes produisent ce motif ; une preuve indépendante peut le requalifier.','{}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

UPDATE code_articles SET
    title='Différence entre domaine présenté et lien intermédiaire',
    principle='Une différence statique entre le texte affiché et un lien intermédiaire déclenche une vérification de la destination finale ; elle ne démontre pas seule une tromperie.',
    default_direction='neutral', default_strength=0, severity='info',
    limitations='Les liens de suivi authentifiés utilisent couramment un apex intermédiaire distinct.'
WHERE article_code='URL-002';

UPDATE code_articles SET
    title='Score agrégé Rspamd',
    principle='Le score agrégé résume les symboles Rspamd et ne constitue jamais une preuve indépendante de ceux-ci.',
    default_direction='neutral', default_strength=0, severity='info',
    limitations='Examiner les symboles constitutifs et leurs pondérations ; ne jamais additionner score et symboles.'
WHERE article_code='RSPAMD-003';

UPDATE code_articles SET
    title='Résultat matériel malware ou virus',
    principle='Seul un symbole établissant un malware ou un virus constitue ici une charge matérielle critique.',
    default_direction='adverse', default_strength=100, severity='critical',
    limitations='Les hypothèses de phishing et les listes de réputation disposent d’articles distincts et doivent être corroborées.'
WHERE article_code='RSPAMD-002';

UPDATE code_articles SET
    title='Preuve profonde incomplète',
    principle='Une preuve absente est une limite procédurale, jamais une preuve à charge.',
    default_direction='neutral', default_strength=0, severity='info',
    limitations='La politique peut demander une décision humaine lorsque le manque porte sur une destination activable ou une pièce jointe matérielle.'
WHERE article_code='POLICY-001';

INSERT INTO audit_log(actor, action, payload)
VALUES ('migration','code.evidence_independence_enabled',
        '{"version":"0.4.0","principles":["missing_is_not_adverse","rspamd_no_double_count","final_url_verification","smtp_feedback_footer"]}');
