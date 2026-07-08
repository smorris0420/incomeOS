-- Run in Supabase SQL editor (project: ohzclmscpkxizdxtweps)
-- Adds the `dt` (double-time hours) column to the stubs table.
-- Without this column, double-time hours are silently dropped on every page reload.

alter table stubs
  add column if not exists dt numeric(6,2) not null default 0;

-- Back-fill existing rows (safe — they had no double-time, so 0 is correct)
update stubs set dt = 0 where dt is null;
