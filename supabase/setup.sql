-- Execute no SQL Editor do projeto Supabase.
-- Cada usuário acessa somente sua própria linha em edulogistica_user_data.

create table if not exists public.user_accounts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  created_at timestamptz not null default now(),
  constraint user_accounts_username_format check (username = lower(btrim(username)) and length(username) between 3 and 40)
);

alter table public.user_accounts enable row level security;
grant select on public.user_accounts to authenticated;
drop policy if exists "Users can read their own username" on public.user_accounts;
create policy "Users can read their own username"
  on public.user_accounts for select to authenticated
  using (auth.uid() = user_id);

create or replace function public.create_edulogistica_username()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_username text;
begin
  new_username := lower(btrim(new.raw_user_meta_data ->> 'username'));
  if new_username is not null and new_username <> '' then
    insert into public.user_accounts (user_id, username)
    values (new.id, new_username)
    on conflict (user_id) do update set username = excluded.username;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_edulogistica on auth.users;
create trigger on_auth_user_created_edulogistica
  after insert on auth.users
  for each row execute procedure public.create_edulogistica_username();

revoke all on function public.create_edulogistica_username() from public, anon, authenticated;

create table if not exists public.edulogistica_user_data (
  user_id uuid primary key references auth.users(id) on delete cascade,
  bookings jsonb not null default '[]'::jsonb,
  settings jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.edulogistica_user_data enable row level security;
grant select, insert, update on public.edulogistica_user_data to authenticated;
drop policy if exists "Users can read their own EduLogistica data" on public.edulogistica_user_data;
drop policy if exists "Users can create their own EduLogistica data" on public.edulogistica_user_data;
drop policy if exists "Users can update their own EduLogistica data" on public.edulogistica_user_data;
create policy "Users can read their own EduLogistica data"
  on public.edulogistica_user_data for select to authenticated
  using (auth.uid() = user_id);
create policy "Users can create their own EduLogistica data"
  on public.edulogistica_user_data for insert to authenticated
  with check (auth.uid() = user_id);
create policy "Users can update their own EduLogistica data"
  on public.edulogistica_user_data for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Depois de criar o usuário em Authentication > Users, associe um nome de usuário:
-- insert into public.user_accounts (user_id, username)
-- values ('UUID_DO_USUARIO', 'nome-de-usuario');
