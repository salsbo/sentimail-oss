-- Basculer vers un modèle open source local, un rôle à la fois.
--
-- Tout basculer d'un coup reviendrait à parier : un modèle local qui juge moins
-- bien ne se voit qu'après coup, et ce qui a été livré est livré. Le routage se
-- décide donc par rôle. La conversation ne décide rien - elle lit et explique -
-- alors qu'un verdict engage la livraison : le premier peut passer en local
-- bien avant le second.
--
-- Ce routage ne remplace pas le fournisseur configuré, il le devance. Si le
-- modèle local échoue, l'appel repart chez le fournisseur distant : une panne
-- locale ralentit, elle n'interrompt pas.

ALTER TABLE llm_provider_config
    DROP CONSTRAINT IF EXISTS llm_provider_config_provider_check;
ALTER TABLE llm_provider_config
    ADD CONSTRAINT llm_provider_config_provider_check
    CHECK (provider IN ('deepseek', 'anthropic', 'openai', 'ollama'));

CREATE TABLE IF NOT EXISTS llm_local_routing (
    role text PRIMARY KEY CHECK (role IN ('conversation', 'verdict')),
    model_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    -- Un repli désactivé rend le rôle entièrement dépendant du local : à
    -- n'utiliser qu'une fois la qualité établie sur la durée.
    fallback_enabled boolean NOT NULL DEFAULT true,
    activated_by text NOT NULL DEFAULT 'operator',
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE llm_local_routing IS
    'Rôles servis par un modèle local. Absent ou enabled=false : le rôle passe '
    'par le fournisseur distant configuré.';

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'llm.local_routing_created',
    '{"version":"1.0.0","roles":["conversation","verdict"],"default":"disabled","fallback":"remote"}'
);
