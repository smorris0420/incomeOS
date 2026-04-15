-- Run this in your Supabase SQL editor (project: ohzclmscpkxizdxtweps)
-- Creates the shift_schedules table for the Planner page

create table if not exists shift_schedules (
  id          text        primary key,
  user_id     uuid        not null references auth.users(id) on delete cascade,
  name        text        not null,
  days        jsonb       not null default '[]',   -- array of 7 {start, end, brk} objects
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Index for fast per-user lookups
create index if not exists shift_schedules_user_id_idx
  on shift_schedules (user_id, updated_at desc);

-- Row-level security: each user sees only their own schedules
alter table shift_schedules enable row level security;

drop policy if exists "shift_schedules_own" on shift_schedules;
create policy "shift_schedules_own" on shift_schedules
  for all
  using  (user_id = auth.uid())
  with check (user_id = auth.uid());
