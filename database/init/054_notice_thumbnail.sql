-- L'avis MAIA affiche désormais la capture dans le corps du message, et non
-- plus seulement en pièce jointe : on ne peut pas demander un avis sur un
-- message que le destinataire n'a pas vu.
--
-- Deux exemplaires sont nécessaires, et ils n'ont pas le même rôle. Celui du
-- corps doit rester léger - une capture pèse 211 ko en moyenne, 1,2 Mo au pire,
-- et l'avis part sur un téléphone. Celui de la pièce jointe doit rester
-- intègre : c'est la preuve, elle ne se réduit pas.
--
-- La file d'envoi ne portait qu'un seul fichier. Elle en porte deux : la
-- miniature affichée, rattachée au corps par son identifiant, et l'original
-- joint tel quel. Les colonnes existantes gardent l'original ; les nouvelles
-- portent la miniature, et restent nulles quand elle n'a pas pu être produite -
-- l'avis part alors sans image dans le corps, jamais avec une image cassée.
ALTER TABLE assistant_outbox
    ADD COLUMN IF NOT EXISTS inline_content bytea,
    ADD COLUMN IF NOT EXISTS inline_filename text,
    ADD COLUMN IF NOT EXISTS inline_content_type text;

COMMENT ON COLUMN assistant_outbox.inline_content IS
    'Miniature affichée dans le corps HTML, rattachée par Content-ID.';
COMMENT ON COLUMN assistant_outbox.inline_filename IS
    'Nom de fichier de la miniature ; NULL si aucune miniature.';
COMMENT ON COLUMN assistant_outbox.inline_content_type IS
    'Type MIME de la miniature ; NULL si aucune miniature.';
