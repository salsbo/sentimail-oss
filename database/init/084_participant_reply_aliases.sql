-- Une personne lit ses avis dans une boîte et répond depuis une autre : son
-- logiciel de messagerie agrège plusieurs comptes et signe avec l'identité par
-- défaut. La réponse portait pourtant le jeton de l'avis, donc la preuve
-- d'avoir lu la bonne boîte. Elle était rejetée en silence, et les décisions
-- humaines - la seule vérité dont dispose SentiMail - se perdaient.
--
-- L'adresse de réponse ne devient un alias qu'après une confirmation envoyée à
-- la boîte de l'avis : seul quelqu'un qui la lit peut l'ouvrir. Un avis
-- transféré ne donne donc pas le pouvoir de décider. Une fois suffit.

CREATE TABLE participant_reply_aliases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_email text NOT NULL,
    alias_email text NOT NULL,
    source text NOT NULL DEFAULT 'email_confirmation'
        CHECK (source IN ('email_confirmation', 'operator')),
    confirmed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (lower(participant_email) <> lower(alias_email))
);

CREATE UNIQUE INDEX ux_participant_reply_aliases
    ON participant_reply_aliases (lower(alias_email), lower(participant_email));
CREATE INDEX ix_participant_reply_aliases_alias
    ON participant_reply_aliases (lower(alias_email));

-- Confirmer pour une boîte vaut pour les autres boîtes du même client : une
-- personne dont le client protège deux domaines ne doit pas confirmer deux
-- fois la même adresse de réponse.
CREATE FUNCTION sentimail_reply_alias_confirmed(alias text, expected text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM participant_reply_aliases a
        WHERE lower(a.alias_email)=lower(alias)
          AND sentimail_same_client_mailbox(a.participant_email, expected)
    )
$$;
