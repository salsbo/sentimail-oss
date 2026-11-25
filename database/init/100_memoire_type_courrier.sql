-- Les confirmations portent aussi la série de courrier observée. La preuve
-- DMARC est indispensable ; le nom affiché ne participe jamais à l'identité.
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations, parameters, enabled
)
SELECT id, 'HIST-006', 'Type de courrier déjà confirmé',
       'Au moins deux messages distincts de la même série ont été confirmés légitimes par ce client, sans qualification contraire. La série réunit un domaine From authentifié par DMARC, un envoi de masse et son List-ID, ou à défaut son objet exact normalisé. Sur un domaine mutualisé ou un relais de confidentialité, elle exige aussi la même adresse exacte.',
       'favorable', 20, 'info',
       'Cet indice ne crée aucune autorisation de domaine, ne réduit aucun seuil et ne remplace aucune inspection. Une identité authentifiée peut être compromise. Les preuves matérielles et les limites réelles restent opposables. Il ne se cumule pas avec HIST-001 quand la même adresse est déjà confirmée.',
       '{"clue_code":"HISTORY_CONFIRMED_MAIL_PROFILE","minimum_confirmations":2}'::jsonb, true
FROM code_editions WHERE code_name='Code Sentinel' AND status='active'
ON CONFLICT (edition_id,article_code) DO NOTHING;

-- Figer les faits des anciens retours pendant que leur message existe encore.
-- Référentiel d'infrastructures partagé avec code/{organisation,sender_identity,
-- shared_esp,mail_profile}. Ici il représente l'état à la date de migration.
WITH infrastructure(domain) AS (
    SELECT unnest(ARRAY[
        'aleeas.com',
        'amazonses.com',
        'aol.com',
        'appleid.com',
        'bbox.fr',
        'brevo.com',
        'ccsend.com',
        'cmail19.com',
        'cmail20.com',
        'createsend.com',
        'duck.com',
        'free.fr',
        'gappssmtp.com',
        'gmail.com',
        'gmx.com',
        'gmx.de',
        'gmx.fr',
        'googlegroups.com',
        'googlemail.com',
        'hotmail.com',
        'hotmail.fr',
        'icloud.com',
        'klaviyomail.com',
        'laposte.net',
        'live.com',
        'live.fr',
        'mac.com',
        'mail.ru',
        'mailengine1.com',
        'mailerlite.com',
        'mailgun.net',
        'mailgun.org',
        'mailjet.com',
        'mandrillapp.com',
        'mcdlv.net',
        'mcsv.net',
        'me.com',
        'mg.gg',
        'mlsend.com',
        'mozmail.com',
        'msn.com',
        'mtasv.net',
        'neuf.fr',
        'onmicrosoft.com',
        'orange.fr',
        'outlook.com',
        'outlook.fr',
        'passinbox.com',
        'passmail.net',
        'postmarkapp.com',
        'proton.me',
        'protonmail.com',
        'rsgsv.net',
        'sailthru.com',
        'sendgrid.info',
        'sendgrid.net',
        'sendinblue.com',
        'sfr.fr',
        'simplelogin.co',
        'simplelogin.com',
        'slmail.me',
        'sparkpost.com',
        'sparkpostmail.com',
        'tutanota.com',
        'wanadoo.fr',
        'web.de',
        'yahoo.com',
        'yahoo.fr',
        'yandex.com',
        'yandex.ru',
        'zoho.com'
    ]::text[])
), captured AS (
    SELECT l.id, m.id::text AS message_id, identity.sender,
           split_part(identity.sender,'@',2) AS domain,
           CASE WHEN coalesce(h.list_id,'')<>'' THEN 'list_id' ELSE 'subject' END AS type_kind,
           lower(trim(regexp_replace(coalesce(nullif(h.list_id,''),m.subject,''),'\s+',' ','g'))) AS type_value
    FROM labels l JOIN messages m ON m.id=l.message_id
    CROSS JOIN LATERAL (
        SELECT lower(hr.facts->>'from_address') AS sender
        FROM investigations i JOIN hook_runs hr ON hr.investigation_id=i.id
        WHERE i.message_id=m.id AND hr.hook_name='identity'
        ORDER BY hr.created_at DESC LIMIT 1
    ) identity
    CROSS JOIN LATERAL (
        SELECT CASE WHEN count(*)=1 THEN min(value_decoded) ELSE '' END AS list_id
        FROM headers WHERE message_id=m.id AND name_normalized='list-id'
    ) h
    WHERE l.source='smtp_feedback_user' AND l.is_ground_truth=true
      AND NOT l.context ? 'mail_profile'
      AND identity.sender LIKE '%@%.%'
      AND EXISTS (
          SELECT 1 FROM investigations i JOIN clues c ON c.investigation_id=i.id
          WHERE i.message_id=m.id AND c.clue_code='AUTH_DMARC_PASS'
      )
      AND EXISTS (
          SELECT 1 FROM investigations i JOIN hook_runs hr ON hr.investigation_id=i.id
          WHERE i.message_id=m.id AND hr.hook_name='nature'
            AND hr.facts->>'sending_mode'='bulk'
      )
), profiles AS (
    SELECT c.*, EXISTS (
        SELECT 1 FROM infrastructure s
        WHERE c.domain=s.domain OR right(c.domain,length(s.domain)+1)='.'||s.domain
    ) AS shared
    FROM captured c WHERE length(c.type_value) BETWEEN 1 AND 300
)
UPDATE labels l
SET context=l.context || jsonb_build_object(
    'mail_profile_message_id',p.message_id,
    'mail_profile',jsonb_build_object(
        'version','1', 'sending_mode','bulk',
        'identity_kind',CASE WHEN p.shared THEN 'sender' ELSE 'domain' END,
        'identity',CASE WHEN p.shared THEN p.sender ELSE p.domain END,
        'type_kind',p.type_kind, 'type_value',p.type_value
    )
)
FROM profiles p WHERE l.id=p.id;

CREATE INDEX IF NOT EXISTS ix_labels_mail_profile
    ON labels ((md5((context->'mail_profile')::text)))
    WHERE active=true AND is_ground_truth=true AND source='smtp_feedback_user';
