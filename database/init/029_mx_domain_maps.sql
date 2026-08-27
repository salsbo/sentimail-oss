-- Le MX doit répondre « ce domaine, je le prends » ou « je ne le prends pas »
-- pendant la transaction SMTP, à chaque destinataire, sans redémarrage et sans
-- fichier de configuration à régénérer. La table `domains` devient donc la
-- source directe des relay_domains de Postfix.
--
-- Trois choses manquaient pour que ce soit sûr :
--   1. la casse : le SMTP est insensible à la casse du domaine, la table ne
--      l'était pas ; un domaine enrôlé en « Exemple.org » aurait été refusé ;
--   2. l'index : la recherche du MX filtre sur lower(fqdn), que l'index
--      existant sur (fqdn) ne pouvait pas servir — un balayage complet à
--      chaque destinataire de chaque message ;
--   3. la surface exposée : la requête du MX ne doit voir que le nom du
--      domaine, jamais son jeton de vérification ni son contact.

-- 1. Normalisation. Les domaines déjà enrôlés sont réécrits en minuscules,
-- puis la contrainte empêche qu'un enrôlement futur réintroduise le problème.
-- La comparaison faite en Python (tenancy.active_domains) devient exacte pour
-- la même raison, sans qu'aucun code n'ait à changer.
UPDATE domains SET fqdn = lower(fqdn) WHERE fqdn <> lower(fqdn);

ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_fqdn_lowercase;
ALTER TABLE domains ADD CONSTRAINT domains_fqdn_lowercase
    CHECK (fqdn = lower(fqdn));

-- 2. Index de service du MX : couvre exactement le prédicat des maps Postfix.
CREATE INDEX IF NOT EXISTS ix_domains_active_lower
    ON domains (lower(fqdn)) WHERE status = 'active';

-- 3. Vue de lecture du MX. Elle ne publie que le fqdn : un compromis du
-- conteneur Postfix ne donne pas accès aux jetons de vérification.
CREATE OR REPLACE VIEW mx_relay_domains AS
    SELECT lower(fqdn) AS fqdn
    FROM domains
    WHERE status = 'active';

COMMENT ON VIEW mx_relay_domains IS
    'Domaines que le MX public accepte de recevoir. Lue à chaque RCPT TO par '
    'les maps pgsql: de Postfix (relay_domains et transport_maps). Un domaine '
    'passé en pending ou suspended disparaît de la vue et son courrier est '
    'aussitôt refusé par reject_unauth_destination, sans redémarrage.';

-- Rôle de lecture dédié, préparé mais non activé : le MX se connecte pour
-- l'instant avec le compte applicatif, faute d'un second fichier de secret.
-- Pour le restreindre, il suffit à l'exploitant de lui donner un mot de passe
-- (ALTER ROLE sentimail_v3_mx LOGIN PASSWORD ...), d'écrire ce mot de passe
-- dans secrets/mx_db_password et de pointer le service mx dessus.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentimail_v3_mx') THEN
        CREATE ROLE sentimail_v3_mx NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO sentimail_v3_mx;
GRANT SELECT ON mx_relay_domains TO sentimail_v3_mx;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'mx.relay_domains_resolved_from_database',
    '{"source":"domains.status=active","previously":"static_transport_file"}'
);
