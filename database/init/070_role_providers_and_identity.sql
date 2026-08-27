-- 070 : le moteur LLM se choisit par rôle, et l'identité de l'instance
-- devient une donnée. Deux adaptateurs seulement : openai_compatible
-- (DeepSeek, OpenAI, Mistral, Ollama... même format de dialogue) et
-- anthropic. Le fournisseur nommé disparaît : c'est l'URL qui dit où
-- part le courrier, ce que la console affiche telle quelle.

CREATE TABLE llm_role_providers (
    role text PRIMARY KEY CHECK (role IN ('verdict','conversation')),
    provider text NOT NULL CHECK (provider IN ('anthropic','openai_compatible')),
    base_url text NOT NULL CHECK (base_url ~ '^https?://'),
    model_name text NOT NULL CHECK (model_name <> ''),
    token_limit_param text NOT NULL DEFAULT 'max_tokens'
        CHECK (token_limit_param IN ('max_tokens','max_completion_tokens')),
    secret_filename text NOT NULL CHECK (secret_filename ~ '^[a-z0-9_]{1,64}$'),
    validated_at timestamptz NOT NULL,
    configured_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Reprise de la configuration existante : le singleton actuel vaut pour
-- les deux rôles, comme il valait pour tous les appels jusqu'ici.
INSERT INTO llm_role_providers
    (role, provider, base_url, model_name, token_limit_param,
     secret_filename, validated_at, configured_by)
SELECT r.role,
       CASE c.provider WHEN 'anthropic' THEN 'anthropic'
            ELSE 'openai_compatible' END,
       CASE c.provider
            WHEN 'deepseek' THEN 'https://api.deepseek.com'
            WHEN 'openai' THEN 'https://api.openai.com/v1'
            ELSE 'https://api.anthropic.com' END,
       c.model_name,
       CASE c.provider WHEN 'openai' THEN 'max_completion_tokens'
            ELSE 'max_tokens' END,
       c.secret_filename,
       c.validated_at,
       c.configured_by
FROM llm_provider_config c
CROSS JOIN (VALUES ('verdict'), ('conversation')) AS r(role);

DROP TABLE llm_provider_config;

-- L'identité de l'instance : table vide = replis sur l'environnement,
-- l'instance démarre sans configuration.
CREATE TABLE instance_identity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    action_address text NOT NULL CHECK (action_address <> ''),
    action_aliases text[] NOT NULL DEFAULT '{}',
    assistant_sender text NOT NULL CHECK (assistant_sender <> ''),
    probe_recipient text NOT NULL CHECK (probe_recipient <> ''),
    configured_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
