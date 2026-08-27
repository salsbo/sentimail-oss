-- 071 : certains fournisseurs exigent un champ propriétaire dans le corps
-- (ex. couper le raisonnement) ; la config le porte, jamais le code.

ALTER TABLE llm_role_providers
    ADD COLUMN body_extras jsonb NOT NULL DEFAULT '{}'::jsonb;
