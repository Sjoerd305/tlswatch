-- Chats of a multi-recipient channel (Telegram) that already received an
-- alert, so a retry after a partial failure skips them.
ALTER TABLE alerts ADD COLUMN delivered TEXT NOT NULL DEFAULT '';
