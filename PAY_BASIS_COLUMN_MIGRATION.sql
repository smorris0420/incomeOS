-- Run in Supabase SQL editor (IncomeOS project)
-- Adds the `pay_basis` column to the stubs table so paychecks remember whether
-- they were logged as hourly or salaried. Without this column, pay_basis is
-- silently dropped on every insert/update (same failure mode as the DT column).

alter table stubs
  add column if not exists pay_basis text not null default 'hourly';

-- Back-fill existing rows (safe — all prior paychecks were hourly)
update stubs set pay_basis = 'hourly' where pay_basis is null;
