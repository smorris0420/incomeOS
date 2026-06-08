-- Run in Supabase SQL editor (project: ohzclmscpkxizdxtweps)
-- Adds the `pto` (paid time off hours) column to the stubs table.
-- Separate from sick/vac/fltHol so PT employees who convert to FT keep clean history.

alter table stubs
  add column if not exists pto numeric(6,2) not null default 0;

update stubs set pto = 0 where pto is null;
