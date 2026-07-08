-- Run in Supabase SQL editor (project: ohzclmscpkxizdxtweps)
-- Adds retire_pretax and retire_roth columns to stubs table.
-- Existing retire values are preserved and back-filled into retire_pretax.

alter table stubs
  add column if not exists retire_pretax numeric(8,2),
  add column if not exists retire_roth   numeric(8,2);

-- Back-fill: existing retire data was all pre-tax (Roth support is new)
update stubs
  set retire_pretax = retire,
      retire_roth   = 0
  where retire_pretax is null;

-- Add defaultHours to the settings table (no schema change needed — settings is key/value)
-- Just run this to confirm the settings table exists:
-- select * from settings limit 1;
