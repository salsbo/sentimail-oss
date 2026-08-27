-- Sans tirage à probabilité connue, le taux de faux négatifs n'est pas
-- mesurable. Il est seulement anecdotique : on ne connaît que les indésirables
-- que l'utilisateur a signalés de lui-même, et rien ne dit combien sont passés
-- inaperçus. Le 18 août, la mesure affichait zéro faux négatif sur trois cent
-- soixante-treize messages - un zéro qui ne voulait rien dire, puisque un seul
-- message livré sur deux cent vingt-sept avait été qualifié.
--
-- Cette table est le registre du tirage. Elle porte la probabilité d'inclusion
-- au moment où le message a été choisi, et c'est cette valeur, connue et non
-- subie, qui autorise l'estimateur de Horvitz-Thompson : une réponse obtenue
-- avec une chance sur vingt représente vingt messages.
--
-- Elle ne porte volontairement pas le label. Le label vit dans `labels`, écrit
-- par le chemin ordinaire d'interprétation des réponses ; c'est la jointure qui
-- dit qu'un message qualifié avait été tiré. Rien du chemin de réponse n'a donc
-- besoin de connaître le sondage, et un sondage arrêté n'invalide aucun label.
CREATE TABLE IF NOT EXISTS delivery_samples (
    id bigserial PRIMARY KEY,
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    inclusion_probability double precision NOT NULL
        CHECK (inclusion_probability > 0 AND inclusion_probability <= 1),
    drawn_at timestamptz NOT NULL DEFAULT now(),
    asked_at timestamptz,
    UNIQUE (message_id)
);

CREATE INDEX IF NOT EXISTS ix_delivery_samples_drawn
    ON delivery_samples (drawn_at DESC);

COMMENT ON TABLE delivery_samples IS
    'Registre du sondage aléatoire des messages livrés sans question.';
COMMENT ON COLUMN delivery_samples.inclusion_probability IS
    'Chance d''avoir été tiré, choisie et non subie : sans elle, pas d''estimateur.';
