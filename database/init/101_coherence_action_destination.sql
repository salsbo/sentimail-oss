-- L'identité, le métier et la destination ont chacun leur constat. Une
-- absence de répondant n'accuse personne sans contradiction positive.
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT e.id, v.article_code, v.title, v.principle, v.direction, v.strength,
       v.severity, v.limitations, v.parameters::jsonb, true
FROM code_editions e
CROSS JOIN (VALUES
    ('DEEP-027', 'Cohérence de métier non établie',
     'L''activité publique n''est pas exploitable ou sa comparaison avec le contenu n''a pas abouti. Ce constat est indépendant de l''accord entre le nom affiché et le domaine : cet accord ne dispense jamais de regarder le contenu.',
     'neutral', 0, 'info',
     'Ni preuve de fraude ni preuve de cohérence. Une panne ne devient jamais une absence de répondant.',
     '{"clue_code":"SENDER_ACTIVITY_UNVERIFIED"}'),
    ('DEEP-028', 'Confrontation de la promesse et de la destination',
     'L''opération annoncée dans le message est comparée à la fonction observée de ses liens d''action. Une absence de contradiction n''établit jamais l''honnêteté ; une vérification non concluante reste explicitement non établie.',
     'neutral', 0, 'info',
     'Les images, pieds de page et liens secondaires ne prouvent rien sur l''opération principale. Un domaine tiers, une redirection, une page illisible ou une authentification intermédiaire ne suffisent jamais à établir une contradiction.',
     '{}'),
    ('DEEP-029', 'Destination incompatible avec l''opération annoncée',
     'Une destination effectivement inspectée présente une fonction incompatible avec l''opération annoncée par son bouton ou par le message. Le constat cite exactement la promesse et l''observation qui la contredit, et explique leur incompatibilité.',
     'adverse', 55, 'high',
     'Exige une contradiction positive, jamais un simple manque. Ne prouve seul ni collecte sensible, ni usurpation, ni cloaking. Une vidéo annoncée comme telle, un suivi mutualisé ou une étape de connexion normale ne sont pas des contradictions.',
     '{"clue_code":"URL_ACTION_DESTINATION_MISMATCH"}'),
    ('CORR-019', 'Identité non établie et opération contredite',
     'L''identité revendiquée reste sans répondant ou non vérifiée, et une contradiction positive entre la promesse et la destination d''action est observée (DEEP-029). L''avis de l''utilisateur est exigé avant de donner suite. SPF, DKIM et DMARC ne résolvent aucune de ces deux questions.',
     'adverse', 65, 'high',
     'Le manque d''identité seul ne suffit jamais. Ce faisceau impose ask_user, sans créer une preuve matérielle de danger ni autoriser à inventer une collecte. Une panne seule ne le déclenche pas. Une preuve matérielle indépendante permettant déjà le classement en indésirables garde cet effet.',
     '{"clue_code":"CORRELATION_UNVERIFIED_IDENTITY_DESTINATION","delivery_barrier":"human_review"}')
) AS v(article_code,title,principle,direction,strength,severity,limitations,parameters)
WHERE e.code_name='Code Sentinel' AND e.status='active'
ON CONFLICT (edition_id,article_code) DO NOTHING;

UPDATE code_articles
SET limitations = limitations || ' Le contrôle du domaine ne prouve pas la réalité de l''opération annoncée. Une contradiction promesse-destination reste opposable même sous authentification valide.'
WHERE article_code IN ('AUTH-001','AUTH-003','AUTH-005','DEEP-023');

INSERT INTO audit_log(actor,action,payload)
VALUES ('migration','code.action_destination_coherence',
        '{"articles":["DEEP-027","DEEP-028","DEEP-029","CORR-019"],"identity_and_activity_independent":true,"inconclusive_is_neutral":true}'::jsonb);
