CREATE UNIQUE INDEX ux_assistant_interpretations_message
    ON assistant_interpretations (conversation_message_id);

CREATE UNIQUE INDEX ux_labels_smtp_feedback_message
    ON labels (message_id, ((context->>'conversation_message_id')))
    WHERE source='smtp_feedback_user';
