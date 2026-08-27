ALTER TABLE messages DROP CONSTRAINT messages_delivery_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_delivery_status_check CHECK (
    delivery_status IN (
        'captured','analyzing','held','release_pending','deferred','delivered','consumed'
    )
);

ALTER TABLE delivery_cases DROP CONSTRAINT delivery_cases_state_check;
ALTER TABLE delivery_cases ADD CONSTRAINT delivery_cases_state_check CHECK (state IN (
    'observation_only','analysis_pending','original_delivered','review_notice_pending',
    'awaiting_reply','release_requested','original_released',
    'future_suppression_requested','closed'
));

CREATE TABLE external_analyses (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    subject_kind text NOT NULL CHECK (subject_kind IN ('url','attachment')),
    subject_key text NOT NULL,
    source text NOT NULL,
    status text NOT NULL CHECK (status IN ('ok','error','skipped')),
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_type text,
    error_detail text,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (message_id, subject_kind, subject_key, source)
);

CREATE INDEX ix_external_analyses_message ON external_analyses (message_id, subject_kind);

CREATE TABLE sender_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_email text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('sender','domain')),
    value_normalized text NOT NULL,
    action text NOT NULL CHECK (action IN ('hold')),
    active boolean NOT NULL DEFAULT true,
    source text NOT NULL DEFAULT 'authenticated_smtp_user',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (participant_email, scope, value_normalized, action)
);

CREATE INDEX ix_sender_policies_active
    ON sender_policies (participant_email, scope, value_normalized) WHERE active=true;

ALTER TABLE assistant_outbox ADD COLUMN body_html text;
ALTER TABLE assistant_outbox ADD COLUMN attachment_filename text;
ALTER TABLE assistant_outbox ADD COLUMN attachment_content_type text;
ALTER TABLE assistant_outbox ADD COLUMN attachment_content bytea;

CREATE UNIQUE INDEX ux_delivery_events_original_delivery
    ON delivery_events (case_id)
    WHERE event_type IN ('original_delivered','original_released');

WITH edition AS (
    SELECT id FROM code_editions
    WHERE code_name='Code Sentinel' AND status='active'
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters
)
SELECT edition.id, article_code, title, principle, direction, strength,
       severity, limitations, parameters::jsonb
FROM edition
CROSS JOIN (VALUES
    ('DEEP-001','Redirection inter-apex',
     'Une destination finale située sur un autre apex que le lien initial doit être expliquée.',
     'adverse',55,'high','Les prestataires de suivi et de sécurité réécrivent légitimement des liens.','{}'),
    ('DEEP-002','Formulaire sensible distant',
     'Un formulaire de saisie découvert à destination d’un lien renforce le risque de collecte frauduleuse.',
     'adverse',65,'high','Un formulaire est courant sur un service authentique.','{}'),
    ('DEEP-003','Analyse URL incomplète',
     'Une URL non inspectée ou un sandbox en erreur interdit la livraison automatique.',
     'adverse',55,'high','Une indisponibilité technique n’est pas une preuve de malveillance.','{"forces_doubt":true}'),
    ('DEEP-004','Fichier malveillant ou actif',
     'Un résultat YARA, macro auto-exécutée, action PDF ou membre exécutable est un indice critique.',
     'adverse',100,'critical','Le finding exact et le hash doivent rester auditables.','{}'),
    ('DEEP-005','Analyse fichier incomplète',
     'Un fichier non inspecté, tronqué ou hors budget interdit la livraison automatique.',
     'adverse',70,'high','Une panne du sandbox n’établit pas que le fichier est malveillant.','{"forces_doubt":true}'),
    ('HIST-001','Expéditeur connu et confirmé',
     'Des verdicts humains légitimes cohérents sur le même expéditeur constituent un indice favorable progressif.',
     'favorable',30,'info','La compromission d’un expéditeur connu reste possible.','{"minimum_confirmations":3}'),
    ('HIST-002','Première observation',
     'Un expéditeur jamais observé ne bénéficie d’aucun historique de confiance.',
     'neutral',0,'info','Nouveau ne signifie pas malveillant.','{}'),
    ('HIST-003','Écart comportemental',
     'Un écart important d’heure, taille, pays, apex de liens ou type de pièce jointe par rapport à l’historique augmente le doute.',
     'adverse',35,'medium','Les comportements légitimes changent et les petits historiques sont peu significatifs.','{}'),
    ('DOMAIN-001','Domaine récent',
     'Un domaine créé récemment est plus compatible avec une infrastructure de campagne éphémère et augmente le doute.',
     'adverse',55,'high','Une nouvelle entreprise ou un nouveau domaine peut être parfaitement légitime.','{"high_risk_days":30,"moderate_risk_days":90}'),
    ('POLICY-001','Preuve incomplète',
     'Toute étape obligatoire incomplète impose un verdict indéterminé ou une revue humaine.',
     'adverse',80,'high','L’incomplétude qualifie la certitude, pas l’intention.','{"forces_doubt":true}')
) AS article(article_code,title,principle,direction,strength,severity,limitations,parameters)
ON CONFLICT (edition_id, article_code) DO UPDATE SET
    title=EXCLUDED.title, principle=EXCLUDED.principle,
    default_direction=EXCLUDED.default_direction,
    default_strength=EXCLUDED.default_strength, severity=EXCLUDED.severity,
    limitations=EXCLUDED.limitations, parameters=EXCLUDED.parameters,
    enabled=true;

INSERT INTO audit_log (actor, action, payload)
VALUES ('migration','decision_engine.schema_ready',
        '{"version":"0.3.0","decision_mode_default":false}');
