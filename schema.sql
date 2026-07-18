-- === MERCH VOTE :: Supabase schema ===
-- Идемпотентен: можно запускать повторно.
--
-- ВАЖНО: секрет админа здесь НЕ хранится. При первом запуске поставится
-- заглушка — ты обязан её заменить своим секретом:
--   update app_config set value = 'ТВОЙ_ДЛИННЫЙ_СЕКРЕТ' where key = 'admin_secret';

-- 1. Таблицы
create table if not exists designs (
  id uuid primary key default gen_random_uuid(),
  name text,
  image_url text not null,
  created_at timestamptz default now()
);

create table if not exists votes (
  id uuid primary key default gen_random_uuid(),
  winner_id uuid not null references designs(id) on delete cascade,
  loser_id uuid not null references designs(id) on delete cascade,
  voter_session text,
  created_at timestamptz default now()
);
create index if not exists votes_winner_idx on votes(winner_id);
create index if not exists votes_loser_idx on votes(loser_id);

create table if not exists app_config (
  key text primary key,
  value text not null
);

-- Заглушка секрета для первой установки (существующий не перезаписывается)
insert into app_config (key, value)
values ('admin_secret', 'CHANGE_ME_IMMEDIATELY_TO_A_LONG_RANDOM_STRING')
on conflict (key) do nothing;

-- 2. RLS: включаем
alter table designs   enable row level security;
alter table votes     enable row level security;
alter table app_config enable row level security;

-- 3. Политики: SELECT на designs публичный (голосовалке нужен),
--    INSERT/DELETE на designs — ТОЛЬКО через admin_* RPC (не публично).
--    INSERT на votes публичный.
--    app_config — политик нет, читается только SECURITY DEFINER-функциями.
drop policy if exists "public read designs"    on designs;
drop policy if exists "public insert designs"  on designs;
drop policy if exists "public delete designs"  on designs;
drop policy if exists "public insert votes"    on votes;

create policy "public read designs" on designs for select using (true);
create policy "public insert votes" on votes   for insert with check (true);

-- 4. GRANT'ы: даём анону минимум и явно отзываем то, что раньше могло быть выдано
grant usage on schema public to anon;
grant select on public.designs to anon;
grant insert on public.votes to anon;
revoke insert, update, delete on public.designs from anon;
revoke select, update, delete on public.votes  from anon;
revoke all on public.app_config from anon;

-- 5. Публичные RPC-функции для чтения статистики (требуют секрет)
create or replace function get_leaderboard(secret text)
returns table (
  id uuid,
  name text,
  image_url text,
  wins bigint,
  losses bigint,
  total bigint
)
language plpgsql
security definer
set search_path = public
as $$
declare
  stored text;
begin
  select value into stored from app_config where key = 'admin_secret';
  if stored is null or stored = '' or secret is null or secret <> stored then
    raise exception 'Unauthorized';
  end if;

  return query
  select
    d.id,
    d.name,
    d.image_url,
    coalesce(w.n, 0)::bigint as wins,
    coalesce(l.n, 0)::bigint as losses,
    (coalesce(w.n, 0) + coalesce(l.n, 0))::bigint as total
  from designs d
  left join (select winner_id, count(*) as n from votes group by winner_id) w on w.winner_id = d.id
  left join (select loser_id,  count(*) as n from votes group by loser_id)  l on l.loser_id  = d.id
  order by d.created_at desc;
end;
$$;
grant execute on function get_leaderboard(text) to anon;

create or replace function get_total_votes(secret text)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  stored text;
begin
  select value into stored from app_config where key = 'admin_secret';
  if stored is null or stored = '' or secret is null or secret <> stored then
    raise exception 'Unauthorized';
  end if;
  return (select count(*) from votes);
end;
$$;
grant execute on function get_total_votes(text) to anon;

-- Уникальные голосующие (по voter_session, который каждый браузер генерирует локально)
create or replace function get_total_voters(secret text)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  stored text;
begin
  select value into stored from app_config where key = 'admin_secret';
  if stored is null or stored = '' or secret is null or secret <> stored then
    raise exception 'Unauthorized';
  end if;
  return (select count(distinct voter_session) from votes where voter_session is not null and voter_session <> '');
end;
$$;
grant execute on function get_total_voters(text) to anon;

-- 6. Админ-RPC для мутаций (требуют секрет; недоступны обычному анону)
create or replace function admin_insert_design(secret text, p_name text, p_image_url text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  stored text;
  new_id uuid;
begin
  select value into stored from app_config where key = 'admin_secret';
  if stored is null or stored = '' or secret is null or secret <> stored then
    raise exception 'Unauthorized';
  end if;
  insert into designs (name, image_url) values (p_name, p_image_url) returning id into new_id;
  return new_id;
end;
$$;
grant execute on function admin_insert_design(text, text, text) to anon;

create or replace function admin_delete_design(secret text, p_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  stored text;
begin
  select value into stored from app_config where key = 'admin_secret';
  if stored is null or stored = '' or secret is null or secret <> stored then
    raise exception 'Unauthorized';
  end if;
  delete from designs where id = p_id;
end;
$$;
grant execute on function admin_delete_design(text, uuid) to anon;

-- 7. Storage: бакет для картинок (публичное чтение — нужно голосовалке).
--    Загрузка сейчас разрешена для любого анона, потому что загружает
--    веб-админка тем же анон-ключом. Компенсируется приватностью репо
--    (URL/название бакета не сразу очевидны стороннему).
insert into storage.buckets (id, name, public)
values ('sketches', 'sketches', true)
on conflict (id) do nothing;

drop policy if exists "public read sketches"   on storage.objects;
drop policy if exists "public upload sketches" on storage.objects;
drop policy if exists "public delete sketches" on storage.objects;

create policy "public read sketches"
  on storage.objects for select
  using (bucket_id = 'sketches');

create policy "public upload sketches"
  on storage.objects for insert
  with check (bucket_id = 'sketches');

create policy "public delete sketches"
  on storage.objects for delete
  using (bucket_id = 'sketches');
