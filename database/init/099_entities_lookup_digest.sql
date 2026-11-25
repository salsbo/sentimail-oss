-- Une URL de suivi peut dépasser la taille d'une entrée B-tree. Indexer une
-- empreinte garde le texte intégral et permet de capturer ces messages.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DROP INDEX IF EXISTS ix_entities_lookup;
CREATE INDEX ix_entities_lookup ON entities (entity_type, md5(value_normalized));

COMMIT;
