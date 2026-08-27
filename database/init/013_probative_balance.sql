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
    ('CONTENT-007','Absence de pression sensible',
     'L’absence conjointe d’urgence, de demande de secret et de demande financière constitue un indice à décharge.',
     'favorable',18,'info','Cette absence ne suffit pas à établir la légitimité si une preuve technique de danger existe.','{}'),
    ('RSPAMD-005','Variation d’enveloppe transactionnelle',
     'Une adresse de rebond différente du From, sous le même domaine authentifié, est courante chez les plateformes d’envoi.',
     'neutral',0,'info','La variation reste à corréler avec SPF, DKIM, DMARC et le score global Rspamd.','{}'),
    ('DEEP-006','Convergence de tracking authentifiée',
     'Des liens de tracking issus d’un expéditeur authentifié et convergeant vers un apex également lié directement forment un indice favorable.',
     'favorable',25,'info','Un compte d’envoi compromis reste possible ; une preuve indépendante de danger conserve sa priorité.','{}'),
    ('DEEP-007','Formulaire distant générique',
     'Un formulaire de recherche ou de navigation sans champ sensible est un fait neutre, pas une preuve de collecte frauduleuse.',
     'neutral',0,'info','Un champ sensible, une destination trompeuse ou une réputation malveillante changent la qualification.','{}'),
    ('DEEP-008','Redirection inter-apex non authentifiée',
     'Une redirection inter-apex non expliquée devient une charge faible à moyenne lorsque l’identité émettrice n’est pas authentifiée.',
     'adverse',35,'medium','Ce signal ne suffit jamais seul à établir un cloaking ou un danger.','{}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

UPDATE code_articles SET
    title='Redirection inter-apex à expliquer',
    principle='Une redirection inter-apex est un fait de navigation qui doit être corrélé ; elle ne démontre pas à elle seule un cloaking.',
    default_direction='neutral',
    default_strength=0,
    severity='info',
    limitations='Le tracking, les prestataires d’envoi, les CDN et les domaines de marque produisent couramment ce motif.'
WHERE article_code='DEEP-001';

UPDATE code_articles SET
    title='Formulaire sensible distant',
    principle='Seul un formulaire demandant un secret, un code, un identifiant critique ou une donnée de paiement constitue une charge matérielle.',
    limitations='Un champ de recherche, un formulaire GET générique ou un formulaire sur un service authentique ne constitue pas cette preuve.'
WHERE article_code='DEEP-002';

UPDATE code_articles SET
    limitations='Le symbole exact, sa pondération Rspamd et le score global doivent être examinés ; FORGED_SENDER seul est souvent une variation d’adresse de rebond.'
WHERE article_code='RSPAMD-002';

WITH deduplicated AS (
    SELECT DISTINCT ON (investigation_id, clue_code, direction)
           investigation_id, clue_code, direction, strength
    FROM clues
    ORDER BY investigation_id, clue_code, direction, strength DESC, id
), totals AS (
    SELECT investigation_id,
           coalesce(sum(strength) FILTER (WHERE direction='favorable'),0) AS favorable,
           coalesce(sum(strength) FILTER (WHERE direction='adverse'),0) AS adverse,
           count(*) FILTER (WHERE direction='neutral') AS neutral
    FROM deduplicated
    GROUP BY investigation_id
)
UPDATE investigations i SET
    favorable_points=totals.favorable,
    adverse_points=totals.adverse,
    neutral_clues=totals.neutral,
    summary=i.summary || '{"evidence_totals":"deduplicated_by_clue_family"}'::jsonb
FROM totals WHERE totals.investigation_id=i.id;

INSERT INTO audit_log(actor, action, payload)
VALUES ('migration','code.probative_balance_enabled',
        '{"version":"0.3.0","principle":"charge_defence_deduplicated"}');
