-- Qui SentiMail protège-t-il ? La réponse était une constante d'environnement,
-- écrite dans cinq services : une seule boîte, celle de l'exploitant. Elle
-- devient une donnée, pour que la protection couvre tous les destinataires d'un
-- domaine enrôlé, et plusieurs domaines à la fois.

CREATE TABLE IF NOT EXISTS domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fqdn text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended')),
    -- Contact qui reçoit l'amorçage du fournisseur et les questions du domaine.
    admin_email text,
    verification_token text NOT NULL DEFAULT encode(gen_random_bytes(16), 'hex'),
    verified_at timestamptz,
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_domains_active ON domains (fqdn) WHERE status = 'active';

COMMENT ON TABLE domains IS
    'Domaines protégés. Un destinataire est couvert dès que son domaine est actif.';
COMMENT ON COLUMN domains.verification_token IS
    'Valeur à publier en TXT _sentimail.<fqdn> pour prouver la maîtrise du domaine.';

-- Installation publique : aucun domaine n'est pré-enrôlé. Enrôler un
-- domaine depuis la console d'admin ou par INSERT direct (voir
-- docs/mx-autonome.md).

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'tenancy.protected_domains_enabled',
    '{"authorization":"resolved_from_database","previously":"single_hardcoded_address"}'
);
