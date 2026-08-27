-- Le rDNS que le MX a déjà résolu accompagne l'adresse au registre : aucune
-- requête sortante, il vient du Received (« from HELO (ptr [ip]) »).

ALTER TABLE hostile_smtp_sources ADD COLUMN IF NOT EXISTS rdns text;
