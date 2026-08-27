CREATE TABLE code_editions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code_name text NOT NULL,
    version text NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
    purpose text NOT NULL,
    effective_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (code_name, version)
);

CREATE UNIQUE INDEX ux_code_editions_active
    ON code_editions (code_name) WHERE status = 'active';

CREATE TABLE code_articles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    edition_id uuid NOT NULL REFERENCES code_editions(id),
    article_code text NOT NULL,
    title text NOT NULL,
    principle text NOT NULL,
    default_direction text NOT NULL
        CHECK (default_direction IN ('favorable', 'adverse', 'neutral')),
    default_strength smallint NOT NULL CHECK (default_strength BETWEEN 0 AND 100),
    severity text NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    limitations text NOT NULL,
    parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (edition_id, article_code)
);

CREATE TABLE investigations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    edition_id uuid NOT NULL REFERENCES code_editions(id),
    mode text NOT NULL DEFAULT 'observation'
        CHECK (mode IN ('observation', 'advisory', 'enforcement')),
    status text NOT NULL
        CHECK (status IN ('complete', 'partial', 'error')),
    favorable_points integer NOT NULL DEFAULT 0,
    adverse_points integer NOT NULL DEFAULT 0,
    neutral_clues integer NOT NULL DEFAULT 0,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (message_id, edition_id)
);

CREATE TABLE hook_runs (
    id bigserial PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    hook_name text NOT NULL,
    hook_version text NOT NULL,
    run_order integer NOT NULL,
    status text NOT NULL CHECK (status IN ('ok', 'skip', 'error')),
    duration_ms double precision NOT NULL CHECK (duration_ms >= 0),
    facts jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_type text,
    error_detail text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (investigation_id, run_order)
);

CREATE TABLE clues (
    id bigserial PRIMARY KEY,
    investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    hook_run_id bigint NOT NULL REFERENCES hook_runs(id) ON DELETE CASCADE,
    article_id uuid REFERENCES code_articles(id),
    article_code text NOT NULL,
    clue_code text NOT NULL,
    direction text NOT NULL CHECK (direction IN ('favorable', 'adverse', 'neutral')),
    strength smallint NOT NULL CHECK (strength BETWEEN 0 AND 100),
    confidence double precision NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    statement text NOT NULL,
    facts jsonb NOT NULL DEFAULT '{}'::jsonb,
    provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
    article_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    ordinal integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (hook_run_id, ordinal)
);

CREATE INDEX ix_clues_message_direction
    ON clues (investigation_id, direction, strength DESC);
CREATE INDEX ix_clues_article ON clues (article_code);

CREATE TABLE verdicts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    classification text NOT NULL
        CHECK (classification IN ('legitimate', 'suspect', 'dangerous', 'undetermined')),
    source text NOT NULL,
    confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    rationale text NOT NULL,
    evidence_for bigint[] NOT NULL DEFAULT '{}',
    evidence_against bigint[] NOT NULL DEFAULT '{}',
    model_name text,
    model_version text,
    prompt_version text,
    is_binding boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_verdicts_investigation_created
    ON verdicts (investigation_id, created_at DESC);

CREATE TABLE delivery_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id uuid NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    investigation_id uuid REFERENCES investigations(id) ON DELETE SET NULL,
    assessed_classification text NOT NULL DEFAULT 'undetermined'
        CHECK (assessed_classification IN ('legitimate', 'suspect', 'dangerous', 'undetermined')),
    state text NOT NULL DEFAULT 'observation_only'
        CHECK (state IN (
            'observation_only', 'original_delivered', 'review_notice_pending',
            'awaiting_reply', 'release_requested', 'original_released',
            'future_suppression_requested', 'closed'
        )),
    original_delivery_allowed boolean NOT NULL DEFAULT true,
    binding boolean NOT NULL DEFAULT false,
    opened_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE review_notices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES delivery_cases(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('planned', 'rendered', 'delivered', 'error')),
    explanation text NOT NULL,
    evidence_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    preview_kind text CHECK (preview_kind IN ('text', 'png')),
    preview_content bytea,
    preview_sha256 char(64),
    render_policy text,
    rendered_at timestamptz,
    delivered_at timestamptz,
    error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE smtp_actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id uuid NOT NULL REFERENCES delivery_cases(id) ON DELETE CASCADE,
    action text NOT NULL CHECK (action IN (
        'report_spam', 'release_original', 'mark_legitimate',
        'suppress_future', 'cancel_suppression'
    )),
    token_hash char(64) NOT NULL UNIQUE,
    reply_address text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'consumed', 'expired', 'revoked')),
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    reply_message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
    requested_by text,
    context jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_smtp_actions_pending
    ON smtp_actions (status, expires_at) WHERE status = 'pending';

CREATE TABLE delivery_events (
    id bigserial PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES delivery_cases(id) ON DELETE CASCADE,
    event_type text NOT NULL CHECK (event_type IN (
        'original_delivered', 'review_notice_delivered', 'reply_received',
        'original_release_requested', 'original_released',
        'future_suppression_requested', 'future_suppression_cancelled', 'error'
    )),
    smtp_queue_id text,
    action_id uuid REFERENCES smtp_actions(id) ON DELETE SET NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_delivery_events_case_created
    ON delivery_events (case_id, created_at);

WITH edition AS (
    INSERT INTO code_editions (
        code_name, version, status, purpose, effective_at
    ) VALUES (
        'Code Sentinel', '0.1.0', 'active',
        'Cadre probatoire initial. Observation uniquement, aucune action SMTP.', now()
    )
    ON CONFLICT (code_name, version) DO UPDATE SET purpose = EXCLUDED.purpose
    RETURNING id
)
INSERT INTO code_articles (
    edition_id, article_code, title, principle, default_direction,
    default_strength, severity, limitations
)
SELECT edition.id, article_code, title, principle, direction, strength, severity, limitations
FROM edition
CROSS JOIN (VALUES
    ('AUTH-001', 'DMARC valide',
     'Un DMARC valide établit que le domaine visible est aligné avec une authentification SPF ou DKIM valide.',
     'favorable', 60, 'info',
     'Prouve le contrôle technique du domaine, jamais l’intention ni l’absence de compromission.'),
    ('AUTH-002', 'DMARC invalide',
     'Un échec DMARC constitue un indice fort d’usurpation du domaine visible.',
     'adverse', 70, 'high',
     'Les redirections et listes de diffusion peuvent casser l’authentification.'),
    ('AUTH-003', 'DKIM valide',
     'Une signature DKIM valide établit l’intégrité du contenu signé et le contrôle du domaine signataire.',
     'favorable', 25, 'info',
     'Le domaine signataire peut être un prestataire tiers et ne pas être aligné avec le From.'),
    ('AUTH-004', 'DKIM invalide',
     'Une signature DKIM invalide indique une modification en transit, une erreur ou une signature non fiable.',
     'adverse', 20, 'medium',
     'Un relais légitime peut modifier le corps et casser la signature.'),
    ('AUTH-005', 'SPF valide',
     'SPF valide indique que l’IP est autorisée pour le domaine d’enveloppe.',
     'favorable', 20, 'info',
     'SPF n’authentifie pas nécessairement le From visible.'),
    ('AUTH-006', 'SPF invalide',
     'SPF fail ou softfail indique que l’IP n’est pas autorisée ou seulement tolérée.',
     'adverse', 20, 'medium',
     'Les redirections peuvent provoquer un échec SPF légitime.'),
    ('AUTH-007', 'Authentification non établie',
     'L’absence de résultat d’authentification fiable laisse le fait non établi.',
     'neutral', 0, 'low',
     'L’absence de preuve n’est pas une preuve de fraude.'),
    ('HEADER-001', 'Unicité du From',
     'Un message conforme ne doit pas présenter plusieurs champs From concurrents.',
     'adverse', 70, 'high',
     'Un défaut de génération peut exister sans intention malveillante.'),
    ('HEADER-002', 'Reply-To distinct',
     'Un Reply-To situé sur un autre domaine enregistrable est un indice de redirection d’identité.',
     'adverse', 15, 'low',
     'Ce comportement est courant pour les services clients, formulaires et prestataires.'),
    ('STRUCT-001', 'Message analysable',
     'Un message analysable sans défaut structurel fournit une preuve technique exploitable.',
     'favorable', 5, 'info',
     'La conformité de structure ne prouve ni la légitimité ni l’innocuité.'),
    ('STRUCT-002', 'Défaut de structure',
     'Un défaut de parsing ou de structure MIME réduit la fiabilité de l’analyse.',
     'adverse', 10, 'low',
     'De nombreux générateurs légitimes produisent des écarts mineurs.'),
    ('STRUCT-003', 'Message-ID présent',
     'La présence d’un Message-ID correctement formé facilite la traçabilité du message.',
     'favorable', 3, 'info',
     'Un Message-ID est déclaratif et peut être forgé.'),
    ('STRUCT-004', 'Message-ID absent',
     'L’absence de Message-ID réduit la traçabilité et constitue un indice faible d’anomalie.',
     'adverse', 3, 'low',
     'Certains systèmes légitimes omettent ce champ.'),
    ('DATE-001', 'Date analysable',
     'Une date d’en-tête analysable permet de comparer chronologie déclarée et réception réelle.',
     'favorable', 2, 'info',
     'La date est déclarative et peut être incorrecte.'),
    ('DATE-002', 'Date absente ou invalide',
     'Une date absente ou invalide réduit la cohérence chronologique du dossier.',
     'adverse', 4, 'low',
     'Une erreur de logiciel expéditeur peut suffire à expliquer ce défaut.')
) AS article(article_code, title, principle, direction, strength, severity, limitations);

INSERT INTO audit_log (actor, action, payload)
VALUES ('migration', 'code.edition_seeded', '{"code":"Code Sentinel","version":"0.1.0","mode":"observation"}')
ON CONFLICT DO NOTHING;
