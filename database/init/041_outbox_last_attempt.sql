-- La réconciliation confondait "avis créé il y a longtemps" et "avis bloqué".
--
-- Le gardien de revue déclarait un avis en échec dès que sa date de création
-- dépassait le seuil. Mais un avis re-pris à l'instant par l'assistant garde
-- sa vieille date de création : le gardien pouvait donc le déclarer perdu et
-- livrer l'original en secours pendant que l'envoi réel aboutissait - avis ET
-- original chez l'utilisateur. On mesure désormais l'ancienneté depuis la
-- dernière tentative, pas depuis la création.

ALTER TABLE assistant_outbox
    ADD COLUMN IF NOT EXISTS last_attempt_at timestamptz;

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'outbox.last_attempt_added',
    '{"version":"1.0.0","reason":"reconcile_uses_last_attempt_not_creation"}'
);
