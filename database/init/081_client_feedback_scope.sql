-- Un client peut protéger plusieurs domaines. Les décisions humaines portent
-- sur le client, pas sur le suffixe utilisé par son logiciel de messagerie.
-- Chaque domaine existant reçoit d'abord son propre client : aucun périmètre
-- n'est élargi implicitement par la migration. Le regroupement reste un geste
-- explicite et audité dans la console.

CREATE TABLE clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_clients_name_lower ON clients (lower(name));

ALTER TABLE domains ADD COLUMN client_id uuid REFERENCES clients(id);

INSERT INTO clients (name)
SELECT fqdn FROM domains
ON CONFLICT (lower(name)) DO NOTHING;

UPDATE domains d SET client_id=c.id
FROM clients c
WHERE lower(c.name)=lower(d.fqdn) AND d.client_id IS NULL;

-- Les créations historiques et les outils d'enrôlement n'avaient pas encore
-- de notion de client. Ce déclencheur leur donne un client isolé par défaut ;
-- fournir client_id permet au contraire un rattachement explicite.
CREATE FUNCTION sentimail_assign_domain_client() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.client_id IS NULL THEN
        INSERT INTO clients(name) VALUES (NEW.fqdn)
        ON CONFLICT (lower(name)) DO UPDATE SET updated_at=clients.updated_at
        RETURNING id INTO NEW.client_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_domains_assign_client
BEFORE INSERT ON domains
FOR EACH ROW EXECUTE FUNCTION sentimail_assign_domain_client();

ALTER TABLE domains ALTER COLUMN client_id SET NOT NULL;
CREATE INDEX ix_domains_client ON domains (client_id, fqdn);

-- Même client : portée des règles et de l'apprentissage. L'égalité exacte
-- reste vraie pour les anciennes données dont le domaine ne serait pas enrôlé.
CREATE FUNCTION sentimail_same_client(address_a text, address_b text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT lower(address_a)=lower(address_b) OR EXISTS (
        SELECT 1 FROM domains da JOIN domains db ON db.client_id=da.client_id
        WHERE da.fqdn=split_part(lower(address_a),'@',2)
          AND db.fqdn=split_part(lower(address_b),'@',2)
    )
$$;

-- Une réponse peut changer de domaine au sein du client, mais jamais de boîte.
-- Les deux domaines doivent encore être actifs et vérifiés : le regroupement
-- ne réactive pas un domaine suspendu et ne remplace pas la preuve DNS.
CREATE FUNCTION sentimail_same_client_mailbox(address_a text, address_b text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT lower(address_a)=lower(address_b) OR (
        split_part(lower(address_a),'@',1)=split_part(lower(address_b),'@',1)
        AND EXISTS (
            SELECT 1 FROM domains da JOIN domains db ON db.client_id=da.client_id
            WHERE da.fqdn=split_part(lower(address_a),'@',2)
              AND db.fqdn=split_part(lower(address_b),'@',2)
              AND da.status='active' AND da.verified_at IS NOT NULL
              AND db.status='active' AND db.verified_at IS NOT NULL
        )
    )
$$;

-- B signifie désormais « ne plus m'envoyer ce correspondant ». Ce n'est pas
-- une livraison ni un abandon implicite : c'est une issue terminale, tracée
-- sans appel SMTP.
ALTER TABLE messages DROP CONSTRAINT messages_delivery_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_delivery_status_check CHECK (
    delivery_status IN (
        'captured','analyzing','held','release_pending','deferred','delivered',
        'consumed','undeliverable','suppressed'
    )
);

ALTER TABLE delivery_cases DROP CONSTRAINT IF EXISTS delivery_cases_state_check;
ALTER TABLE delivery_cases ADD CONSTRAINT delivery_cases_state_check CHECK (state IN (
    'observation_only','analysis_pending','original_delivered',
    'original_filed_as_junk','review_notice_pending','awaiting_reply',
    'release_requested','original_released','future_suppression_requested',
    'closed','ignored','policy_suppressed'
));

ALTER TABLE delivery_events DROP CONSTRAINT IF EXISTS delivery_events_event_type_check;
ALTER TABLE delivery_events ADD CONSTRAINT delivery_events_event_type_check CHECK (
    event_type IN (
        'original_delivered','original_filed_as_junk','review_notice_delivered',
        'reply_received','original_release_requested','original_released',
        'future_suppression_requested','future_suppression_cancelled','error',
        'policy_suppressed'
    )
);

CREATE UNIQUE INDEX ux_delivery_events_policy_suppressed
    ON delivery_events(case_id) WHERE event_type='policy_suppressed';

INSERT INTO audit_log(actor,action,payload) VALUES (
    'migration','feedback.client_scope_and_terminal_suppression',
    '{"version":"1.0.0","default_scope":"one_client_per_existing_domain"}'
);
