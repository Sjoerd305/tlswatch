-- The reference a delivered alert went out under (the SMTP Message-ID), to
-- match it with the mail relay's logs.
ALTER TABLE alerts ADD COLUMN ref TEXT NOT NULL DEFAULT '';
