-- The reference a delivered alert went out under: the SMTP Message-ID, or
-- for Telegram "chat:message_id" per chat, to trace it outside tlswatch.
ALTER TABLE alerts ADD COLUMN ref TEXT NOT NULL DEFAULT '';
