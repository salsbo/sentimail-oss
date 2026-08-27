-- Un destinataire que le relais refuse définitivement (5.x.x) n'a pas d'issue :
-- ni livraison, ni avis MAIA, ni reprise. Faute d'état pour le dire, ces
-- dossiers restaient « deferred » à vie et le superviseur les signalait sans
-- fin. « undeliverable » est cet état terminal, côté message comme côté avis.

ALTER TABLE messages DROP CONSTRAINT messages_delivery_status_check;
ALTER TABLE messages ADD CONSTRAINT messages_delivery_status_check CHECK (
    delivery_status IN (
        'captured','analyzing','held','release_pending','deferred','delivered',
        'consumed','undeliverable'
    )
);

ALTER TABLE assistant_outbox DROP CONSTRAINT assistant_outbox_status_check;
ALTER TABLE assistant_outbox ADD CONSTRAINT assistant_outbox_status_check CHECK (
    status IN ('pending','sending','sent','error','undeliverable')
);
