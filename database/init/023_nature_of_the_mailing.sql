-- Nature de l'envoi. Le Code savait reconnaître la tromperie, pas le cadre dans
-- lequel un message arrive. Un envoi commercial de masse n'exerce aucune
-- pression : son absence de coercition finissait donc par le créditer.

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
    ('NATURE-001','Envoi de masse identifié',
     'Les en-têtes normalisés de diffusion décrivent le cadre d’envoi d’un message : diffusion de masse, message automatique ou échange conversationnel.',
     'neutral',0,'info','Un envoi de masse est parfaitement légitime lorsque le destinataire l’a demandé. Ce fait décrit un cadre, jamais une intention.','{"context_kind":"sending_mode"}'),
    ('NATURE-002','Envoi de masse sans lien d’abonnement établi',
     'Un envoi de masse dont l’expéditeur n’a aucun échange antérieur avec le destinataire ni confirmation humaine ne peut pas se prévaloir d’un abonnement consenti.',
     'adverse',20,'low','Un premier envoi légitime reste possible : ce signal ne suffit jamais seul à établir un danger, et il disparaît dès qu’un échange ou une confirmation existe.','{"context_kind":"unsolicited_bulk","requires_history":true}'),
    ('NATURE-003','Promesses invérifiables dans un envoi promotionnel',
     'Un envoi promotionnel qui repose sur des promesses invérifiables de santé ou d’enrichissement relève d’un registre de sollicitation non désirée, distinct de la communication commerciale ordinaire.',
     'adverse',25,'low','Le registre du discours n’est jamais une preuve matérielle. Il décrit une rhétorique, pas un produit ni un secteur, et ne peut pas fonder seul une qualification de danger.','{"context_kind":"promotional_claims"}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

UPDATE code_articles SET
    limitations=
        'L’absence de pression ne qualifie que le risque de coercition. Elle ne '
        'devient jamais un indice favorable pour un envoi de masse, dont la '
        'légitimité dépend du lien d’abonnement et non du ton employé.'
WHERE article_code='CONTENT-007';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'code.mailing_nature_enabled',
    '{"hook":"nature","articles":["NATURE-001","NATURE-002","NATURE-003"],"content_007_scoped_to_coercion":true}'
);
