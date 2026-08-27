-- Les désaccords humain/modèle partaient par courrier à chaque cycle
-- d'entretien, puis s'oubliaient : rien ne distinguait un écart déjà analysé
-- d'un écart jamais vu, et la fenêtre de sept jours faisait renaître les mêmes
-- constats à chaque glissement. Un écart devient un enregistrement qu'on
-- instruit comme une vulnérabilité : il naît quand un jugement humain
-- contredit un verdict, reste ouvert tant qu'un exploitant ne l'a pas
-- acquitté, et ne sort jamais des mesures - l'acquittement classe le dossier,
-- il ne réécrit pas l'histoire.

CREATE TABLE IF NOT EXISTS discrepancies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
    -- Un écart par jugement humain : le label est la source du désaccord, et
    -- ses colonnes propres (expéditeur, destinataire, objet témoin) survivent
    -- à la purge du message d'origine.
    label_id bigint NOT NULL UNIQUE REFERENCES labels(id) ON DELETE CASCADE,
    human_label text NOT NULL,
    model_classification text NOT NULL,
    model_confidence double precision,
    direction text NOT NULL CHECK (direction IN (
        'laisse_passer', 'erreur_de_qualification',
        'demande_au_lieu_de_classer', 'demande_au_lieu_de_livrer'
    )),
    prompt_version text NOT NULL,
    -- La date du désaccord est celle du jugement humain, pas celle du cycle
    -- d'entretien qui l'a constaté : les mesures 7 j / 30 j comptent des
    -- événements, pas des passages de l'agent.
    created_at timestamptz NOT NULL,
    acknowledged_at timestamptz,
    acknowledged_by text
);

CREATE INDEX IF NOT EXISTS ix_discrepancies_open
    ON discrepancies (created_at DESC) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_discrepancies_created
    ON discrepancies (created_at DESC);

INSERT INTO audit_log(actor, action, payload)
VALUES (
    'migration',
    'discrepancies.table_added',
    jsonb_build_object(
        'reason', 'disagreements_become_acknowledgeable_records',
        'migration', '073_discrepancies'
    )
);
