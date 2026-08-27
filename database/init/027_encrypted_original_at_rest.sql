-- Le message original était conservé en clair : la rétention bornait la durée
-- de conservation, pas sa confidentialité, et une sauvegarde chiffrée ne
-- protège pas la base elle-même. La colonne indique désormais comment chaque
-- original est protégé, ce qui permet une bascule progressive et sans perte.

ALTER TABLE messages ADD COLUMN IF NOT EXISTS raw_eml_encryption text;

COMMENT ON COLUMN messages.raw_eml_encryption IS
    'NULL : contenu hérité en clair. aes-256-gcm-v1 : chiffré avec la clé montée en secret.';

CREATE INDEX IF NOT EXISTS ix_messages_plaintext_originals
    ON messages (captured_at)
    WHERE raw_eml IS NOT NULL AND raw_eml_encryption IS NULL;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'crypto.original_at_rest_enabled',
    '{"algorithm":"aes-256-gcm-v1","key":"mounted-secret","legacy_plaintext_supported":true}'
);
