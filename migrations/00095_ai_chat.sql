-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig95_up;
CREATE PROCEDURE hpg_mig95_up()
BEGIN
    -- ai_chat_sessions: one conversation thread per user, tied to a provider.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ai_chat_sessions') THEN
        CREATE TABLE ai_chat_sessions (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id    BIGINT UNSIGNED NOT NULL,
            title      VARCHAR(200)    NOT NULL DEFAULT '',
            provider   VARCHAR(32)     NOT NULL DEFAULT '',
            created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_aichat_sess_user (user_id),
            -- fk name must be globally unique per schema; fk_acs_user is taken by admin_scope (mig 00057)
            CONSTRAINT fk_aichat_sess_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    END IF;

    -- ai_chat_messages: individual turns within a session; MEDIUMTEXT for large tool responses.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ai_chat_messages') THEN
        CREATE TABLE ai_chat_messages (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            session_id BIGINT UNSIGNED NOT NULL,
            role       VARCHAR(16)     NOT NULL,
            content    MEDIUMTEXT      NOT NULL,
            created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_aichat_msg_session (session_id),
            CONSTRAINT fk_aichat_msg_session FOREIGN KEY (session_id) REFERENCES ai_chat_sessions(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    END IF;
END;
CALL hpg_mig95_up();
DROP PROCEDURE IF EXISTS hpg_mig95_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig95_down;
CREATE PROCEDURE hpg_mig95_down()
BEGIN
    -- drop child first to avoid FK constraint violation.
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ai_chat_messages') THEN
        DROP TABLE ai_chat_messages;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ai_chat_sessions') THEN
        DROP TABLE ai_chat_sessions;
    END IF;
END;
CALL hpg_mig95_down();
DROP PROCEDURE IF EXISTS hpg_mig95_down;
-- +goose StatementEnd
