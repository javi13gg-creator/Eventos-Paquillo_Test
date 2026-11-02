-- PAQUILLO EVENTS · esquema inicial Supabase
-- Ejecutar DESPUÉS de crear las 23 cuentas en Authentication > Users.

create table if not exists public.user_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  role text not null default 'member' check (role in ('member','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.access_logs (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists access_logs_user_created_idx on public.access_logs(user_id, created_at desc);

-- Crear perfiles a partir del correo interno asignado a cada usuario.
insert into public.user_profiles(user_id, username, role)
select id,
  case lower(split_part(email,'@',1))
    when 'leti' then 'Leti'
    when 'adri' then 'Adri'
    when 'alba' then 'Alba'
    when 'carla' then 'Carla'
    when 'david' then 'David'
    when 'diego' then 'Diego'
    when 'ines' then 'Ines'
    when 'ivan' then 'Iván'
    when 'joaquin' then 'Joaquín'
    when 'jb' then 'JB'
    when 'jorge-r' then 'Jorge R'
    when 'julia' then 'Julia'
    when 'laura' then 'Laura'
    when 'maria' then 'María'
    when 'mireia' then 'Mireia'
    when 'richy' then 'Richy'
    when 'roman' then 'Román'
    when 'rodri' then 'Rodri'
    when 'sara' then 'Sara'
    when 'santi' then 'Santi'
    when 'sandra' then 'Sandra'
    when 'sofia' then 'Sofía'
    when 'javi' then 'Javi'
    else null
  end,
  case when lower(split_part(email,'@',1))='javi' then 'admin' else 'member' end
from auth.users
where lower(split_part(email,'@',2))='paquillo-events.com'
on conflict (user_id) do update set username=excluded.username, role=excluded.role;

-- Evita perfiles con un alias no reconocido.
delete from public.user_profiles where username is null;

create or replace function public.paqui_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_profiles
    where user_id = auth.uid() and role = 'admin'
  );
$$;

alter table public.user_profiles enable row level security;
alter table public.access_logs enable row level security;

drop policy if exists "Users can read own profile" on public.user_profiles;
create policy "Users can read own profile" on public.user_profiles
for select to authenticated using (user_id = auth.uid());

drop policy if exists "Authenticated users can log own access" on public.access_logs;
create policy "Authenticated users can log own access" on public.access_logs
for insert to authenticated with check (user_id = auth.uid());

drop policy if exists "Only Javi can read access logs" on public.access_logs;
create policy "Only Javi can read access logs" on public.access_logs
for select to authenticated using (public.paqui_is_admin());

-- Permite al administrador ver el nombre asociado a cada registro en la consulta de estadísticas.
drop policy if exists "Javi can read all profiles" on public.user_profiles;
create policy "Javi can read all profiles" on public.user_profiles
for select to authenticated using (public.paqui_is_admin());
