-- Les nouvelles occurrences réutilisent une observation fraîche sans retoucher
-- celles qui ont déjà servi de preuve. Les empreintes bornent les entrées B-tree ;
-- les requêtes comparent aussi le texte entier pour écarter une collision.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

CREATE INDEX ix_entities_pending_enrichment
    ON entities (entity_type, md5(value_normalized), id)
    WHERE enrichment_id IS NULL AND entity_type IN ('domain', 'ip');

CREATE INDEX ix_enrichments_fresh_lookup
    ON enrichments (entity_type, md5(value_normalized), observed_at DESC, id DESC)
    WHERE source='rdap+dns';

COMMIT;
