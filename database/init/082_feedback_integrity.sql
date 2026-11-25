-- 082 : réparer les effets durables des retours SMTP et poser le point de
-- départ du contrôle continu.
--
-- Deux régressions génériques sont reprises : les choix des récapitulatifs
-- avaient enregistré une qualification sans ses signaux observés, et les
-- réponses préremplies en toutes lettres avaient parfois livré l'original
-- sans poser la liste blanche correspondant au choix A. Une décision opposée
-- plus récente est toujours préservée : elle représente un changement d'avis.

CREATE TEMP TABLE feedback_integrity_stats (
    name text PRIMARY KEY,
    repaired bigint NOT NULL
);

WITH repaired AS (
    UPDATE labels l
    SET context=l.context || jsonb_build_object('signals', observed.codes),
        updated_at=now()
    FROM (
        SELECT i.message_id,
               jsonb_agg(DISTINCT c.clue_code) AS codes
        FROM clues c
        JOIN investigations i ON i.id=c.investigation_id
        WHERE c.direction <> 'neutral'
        GROUP BY i.message_id
    ) observed
    WHERE l.message_id=observed.message_id
      AND l.source='smtp_feedback_user'
      AND l.active=true
      AND (
          jsonb_typeof(l.context->'signals') IS DISTINCT FROM 'array'
          OR jsonb_array_length(
              CASE
                WHEN jsonb_typeof(l.context->'signals')='array'
                THEN l.context->'signals'
                ELSE '[]'::jsonb
              END
          )=0
      )
    RETURNING l.id
)
INSERT INTO feedback_integrity_stats(name,repaired)
SELECT 'label_signals',count(*) FROM repaired;

-- Une seule intention courante par client et expéditeur : si B a suivi A, B
-- gagne ; si une règle a été modifiée après le retour, la migration n'y touche
-- pas. Le client reste la frontière de portée définie par la migration 081.
CREATE TEMP TABLE feedback_policy_repair_candidates AS
WITH events AS (
    SELECT
        l.id,
        l.created_at,
        lower(l.sender_normalized) AS sender,
        lower(l.participant_email) AS participant,
        coalesce(d.client_id::text,lower(l.participant_email)) AS client_key,
        CASE
          WHEN l.context->>'interpretation'='digest_choice'
               AND l.label='legitimate' THEN 'allow'
          WHEN l.context->>'interpretation'='digest_choice'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          WHEN ai.binding=true
               AND ai.requested_action='release_original'
               AND l.label='legitimate' THEN 'allow'
          WHEN ai.binding=true
               AND ai.requested_action='suppress_future'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          WHEN ai.binding=true
               AND ai.raw_response->>'choice'='A'
               AND l.label='legitimate' THEN 'allow'
          WHEN ai.binding=true
               AND ai.raw_response->>'choice'='B'
               AND l.label IN ('spam','dangerous','suspect') THEN 'hold'
          ELSE NULL
        END AS expected_policy
    FROM labels l
    LEFT JOIN assistant_interpretations ai
      ON ai.conversation_message_id::text=l.context->>'conversation_message_id'
    LEFT JOIN domains d
      ON d.fqdn=split_part(lower(l.participant_email),'@',2)
    WHERE l.source='smtp_feedback_user'
      AND l.active=true
      AND nullif(l.sender_normalized,'') IS NOT NULL
      AND position('@' in l.sender_normalized)>0
      AND nullif(l.participant_email,'') IS NOT NULL
      AND position('@' in l.participant_email)>0
), latest AS (
    SELECT DISTINCT ON (client_key,sender)
           id,created_at,sender,participant,client_key,expected_policy
    FROM events
    WHERE expected_policy IS NOT NULL
    ORDER BY client_key,sender,created_at DESC,id DESC
)
SELECT latest.*
FROM latest
WHERE NOT EXISTS (
    SELECT 1 FROM sender_policies p
    WHERE sentimail_same_client(p.participant_email,latest.participant)
      AND p.scope='sender'
      AND p.value_normalized=latest.sender
      AND p.action=latest.expected_policy
      AND p.active=true
)
AND NOT EXISTS (
    SELECT 1 FROM sender_policies p
    WHERE sentimail_same_client(p.participant_email,latest.participant)
      AND p.scope='sender'
      AND p.value_normalized=latest.sender
      AND p.active=true
      AND p.updated_at > latest.created_at
);

-- Une règle opposée plus ancienne est précisément l'état que le retour devait
-- remplacer. Elle est désactivée avant l'upsert, comme le fait le code courant.
UPDATE sender_policies p
SET active=false,updated_at=now()
FROM feedback_policy_repair_candidates c
WHERE sentimail_same_client(p.participant_email,c.participant)
  AND p.scope='sender'
  AND p.value_normalized=c.sender
  AND p.action<>c.expected_policy
  AND p.active=true
  AND p.updated_at <= c.created_at;

INSERT INTO sender_policies (
    participant_email,scope,value_normalized,action,active,source
)
SELECT participant,'sender',sender,expected_policy,true,
       'migration_082_feedback_integrity'
FROM feedback_policy_repair_candidates
ON CONFLICT (participant_email,scope,value_normalized,action)
DO UPDATE SET active=true,source=excluded.source,updated_at=now();

INSERT INTO feedback_integrity_stats(name,repaired)
SELECT 'sender_policies',count(*) FROM feedback_policy_repair_candidates;

-- Ce marqueur est lu par le watchdog. Tout retour créé après lui doit produire
-- ses effets dans les deux minutes, faute de quoi l'exploitation est dégradée.
INSERT INTO audit_log(actor,action,payload)
SELECT
    'migration',
    'feedback.integrity_repaired',
    jsonb_build_object(
        'version','1.0.0',
        'label_signals_repaired',coalesce(
            (SELECT repaired FROM feedback_integrity_stats
             WHERE name='label_signals'),0
        ),
        'sender_policies_repaired',coalesce(
            (SELECT repaired FROM feedback_integrity_stats
             WHERE name='sender_policies'),0
        ),
        'watchdog_grace_seconds',120
    );

DROP TABLE feedback_policy_repair_candidates;
DROP TABLE feedback_integrity_stats;
