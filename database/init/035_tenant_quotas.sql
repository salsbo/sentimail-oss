-- Le budget d'appels au modèle appartenait à tout le monde, donc à personne.
--
-- Les verdicts se comptaient globalement : un domaine qui reçoit beaucoup
-- épuisait le quota des autres, et ces autres basculaient en retenue sans que
-- rien chez eux ne l'explique. Les appels de l'assistant se comptaient par
-- adresse, ce qui protège un utilisateur d'un autre mais ne protège aucun
-- domaine du voisin.
--
-- Deux plafonds désormais, et ils ne servent pas la même chose. Celui du
-- domaine assure l'équité : nul ne mange la part d'autrui. Le plafond global
-- reste au-dessus, car la dépense totale, elle, est bien commune.

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS assistant_hourly_limit integer,
    ADD COLUMN IF NOT EXISTS assistant_daily_limit integer,
    ADD COLUMN IF NOT EXISTS verdict_hourly_limit integer,
    ADD COLUMN IF NOT EXISTS verdict_daily_limit integer;

COMMENT ON COLUMN domains.assistant_hourly_limit IS
    'Plafond horaire du domaine pour les échanges. NULL : valeur par défaut de '
    'l''instance.';

-- Sans le domaine sur l'événement, on ne peut compter que globalement.
ALTER TABLE llm_call_events ADD COLUMN IF NOT EXISTS domain_fqdn text;
ALTER TABLE verdict_llm_call_events ADD COLUMN IF NOT EXISTS domain_fqdn text;

CREATE INDEX IF NOT EXISTS ix_llm_call_events_domain
    ON llm_call_events (domain_fqdn, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_verdict_llm_call_events_domain
    ON verdict_llm_call_events (domain_fqdn, created_at DESC);

-- Les événements déjà enregistrés portent l'adresse : le domaine s'en déduit.
UPDATE llm_call_events
SET domain_fqdn = lower(split_part(participant_email, '@', 2))
WHERE domain_fqdn IS NULL AND participant_email LIKE '%@%';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'quotas.per_tenant_enabled',
    '{"version":"1.0.0","scope":["assistant","verdict"],"global_ceiling":"kept"}'
);
