ALTER TABLE labels ADD COLUMN active boolean NOT NULL DEFAULT true;
ALTER TABLE labels ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX ix_labels_active_training
    ON labels (is_ground_truth, label)
    WHERE active=true;

ALTER TABLE assistant_interpretations
    DROP CONSTRAINT assistant_interpretations_requested_action_check;
ALTER TABLE assistant_interpretations
    ADD CONSTRAINT assistant_interpretations_requested_action_check CHECK (
        requested_action IS NULL OR requested_action IN (
            'release_original', 'suppress_future', 'cancel_suppression',
            'record_feedback', 'explain', 'list_rules', 'update_rule',
            'disable_rule', 'restore_rule', 'none'
        )
    );
