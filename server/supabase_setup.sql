-- =====================================================================
--  Iceberg Client — сервер аккаунтов, подписок и чата (Supabase)
--  Как применить: Supabase → SQL Editor → New query → вставить всё → Run.
--  Скрипт можно запускать повторно.
--
--  Вход по нику и паролю, без почты. Таблицы закрыты от прямого доступа,
--  лаунчер работает только через функции ниже. Админ — игрок с ником detanetov.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Таблицы ----------
create table if not exists public.players (
  id          bigserial primary key,
  username    text not null check (username ~ '^[A-Za-z0-9_]{3,16}$'),
  pass_hash   text not null,
  created_at  timestamptz not null default now(),
  last_seen   timestamptz
);
create unique index if not exists players_username_lower on public.players (lower(username));

create table if not exists public.sessions (
  token       uuid primary key default gen_random_uuid(),
  player_id   bigint not null references public.players on delete cascade,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default now() + interval '30 days'
);

create table if not exists public.subscriptions (
  player_id   bigint primary key references public.players on delete cascade,
  plan        text,                 -- последний тариф: 30d / 180d / 360d / lifetime
  expires_at  timestamptz,          -- до какого числа (null при lifetime)
  lifetime    boolean not null default false,
  beta        boolean not null default false,
  updated_at  timestamptz not null default now(),
  updated_by  text
);

create table if not exists public.messages (
  id          bigserial primary key,
  player_id   bigint not null references public.players on delete cascade,
  username    text not null,
  body        text not null check (char_length(body) between 1 and 300),
  created_at  timestamptz not null default now()
);
create index if not exists messages_id_desc on public.messages (id desc);

-- Прямой доступ к таблицам закрыт: RLS включён, политик нет
alter table public.players       enable row level security;
alter table public.sessions      enable row level security;
alter table public.subscriptions enable row level security;
alter table public.messages      enable row level security;
revoke all on public.players, public.sessions, public.subscriptions, public.messages from anon, authenticated;

-- ---------- Внутренние функции ----------
create or replace function public._player(p_token uuid) returns public.players
language plpgsql security definer set search_path = public, extensions as $$
declare pl players;
begin
  select p.* into pl from sessions s join players p on p.id = s.player_id
  where s.token = p_token and s.expires_at > now();
  if pl.id is null then raise exception 'Сессия истекла, войди заново' using errcode = 'P0001', hint = 'session'; end if;
  return pl;
end $$;

create or replace function public._is_admin(pl public.players) returns boolean
language sql immutable as $$ select lower(pl.username) = 'detanetov' $$;

create or replace function public._active(s public.subscriptions) returns boolean
language sql stable as $$
  select s.player_id is not null and (s.lifetime or (s.expires_at is not null and s.expires_at > now()));
$$;

create or replace function public._new_session(pid bigint) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare t uuid;
begin
  delete from sessions where expires_at < now();
  insert into sessions (player_id) values (pid) returning token into t;
  update players set last_seen = now() where id = pid;
  return t;
end $$;

-- ---------- Аккаунты ----------
drop function if exists public.register(text, text);
create function public.register(p_username text, p_password text)
returns table (token uuid, username text)
language plpgsql security definer set search_path = public, extensions as $$
declare pid bigint;
begin
  p_username := btrim(coalesce(p_username, ''));
  if p_username !~ '^[A-Za-z0-9_]{3,16}$' then
    raise exception 'Ник: от 3 до 16 латинских букв, цифр или _';
  end if;
  if char_length(coalesce(p_password, '')) < 6 then
    raise exception 'Пароль должен быть не короче 6 символов';
  end if;
  if exists (select 1 from players p where lower(p.username) = lower(p_username)) then
    raise exception 'Ник % уже занят', p_username;
  end if;
  insert into players (username, pass_hash) values (p_username, crypt(p_password, gen_salt('bf', 8)))
  returning id into pid;
  return query select _new_session(pid), p_username;
end $$;

drop function if exists public.login(text, text);
create function public.login(p_username text, p_password text)
returns table (token uuid, username text)
language plpgsql security definer set search_path = public, extensions as $$
declare pl players;
begin
  select * into pl from players p where lower(p.username) = lower(btrim(coalesce(p_username, '')));
  if pl.id is null or pl.pass_hash <> crypt(coalesce(p_password, ''), pl.pass_hash) then
    perform pg_sleep(0.4);
    raise exception 'Неверный ник или пароль';
  end if;
  return query select _new_session(pl.id), pl.username;
end $$;

drop function if exists public.logout(uuid);
create function public.logout(p_token uuid) returns void
language sql security definer set search_path = public as $$
  delete from sessions where token = p_token;
$$;

-- Кто я и какая подписка (заодно отмечает «в сети»)
drop function if exists public.me(uuid);
create function public.me(p_token uuid)
returns table (username text, is_admin boolean, plan text, expires_at timestamptz,
               lifetime boolean, beta boolean, active boolean)
language plpgsql security definer set search_path = public, extensions as $$
declare pl players; s subscriptions;
begin
  pl := _player(p_token);
  update players set last_seen = now() where id = pl.id;
  select * into s from subscriptions where player_id = pl.id;
  return query select pl.username, _is_admin(pl), s.plan, s.expires_at,
    coalesce(s.lifetime, false), coalesce(s.beta, false) and coalesce(_active(s), false),
    coalesce(_active(s), false);
end $$;

drop function if exists public.online_players(uuid);
create function public.online_players(p_token uuid)
returns table (username text, last_seen timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _player(p_token);
  return query select p.username, p.last_seen from players p
    where p.last_seen > now() - interval '2 minutes' order by lower(p.username);
end $$;

-- ---------- Чат ----------
drop function if exists public.chat_list(uuid, bigint);
create function public.chat_list(p_token uuid, p_after bigint default 0)
returns table (id bigint, username text, body text, created_at timestamptz)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _player(p_token);
  return query select * from (
    select m.id, m.username, m.body, m.created_at from messages m
    where m.id > coalesce(p_after, 0) order by m.id desc limit 60
  ) t order by t.id;
end $$;

drop function if exists public.chat_send(uuid, text);
create function public.chat_send(p_token uuid, p_body text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare pl players;
begin
  pl := _player(p_token);
  p_body := btrim(coalesce(p_body, ''));
  if char_length(p_body) = 0 then return; end if;
  if char_length(p_body) > 300 then raise exception 'Сообщение длиннее 300 символов'; end if;
  if exists (select 1 from messages where player_id = pl.id and created_at > now() - interval '1 second') then
    raise exception 'Слишком часто, подожди секунду';
  end if;
  insert into messages (player_id, username, body) values (pl.id, pl.username, p_body);
end $$;

drop function if exists public.chat_delete(uuid, bigint);
create function public.chat_delete(p_token uuid, p_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _is_admin(_player(p_token)) then raise exception 'Только для администратора'; end if;
  delete from messages where id = p_id;
end $$;

-- ---------- Админ ----------
drop function if exists public.admin_list_users(uuid, text);
create function public.admin_list_users(p_token uuid, q text default '')
returns table (username text, created_at timestamptz, last_seen timestamptz, plan text,
               expires_at timestamptz, lifetime boolean, beta boolean, active boolean)
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not _is_admin(_player(p_token)) then raise exception 'Только для администратора'; end if;
  return query
    select p.username, p.created_at, p.last_seen, s.plan, s.expires_at,
           coalesce(s.lifetime, false), coalesce(s.beta, false), coalesce(_active(s), false)
    from players p left join subscriptions s on s.player_id = p.id
    where coalesce(q, '') = '' or p.username ilike '%' || q || '%'
    order by p.created_at desc limit 200;
end $$;

-- tariff: '30d' | '180d' | '360d' | 'lifetime' | 'beta' | 'remove_beta' | 'none'
drop function if exists public.admin_set_subscription(uuid, text, text);
create function public.admin_set_subscription(p_token uuid, target text, tariff text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  admin players;
  pid   bigint;
  s     subscriptions;
  days  int;
begin
  admin := _player(p_token);
  if not _is_admin(admin) then raise exception 'Только для администратора'; end if;
  select id into pid from players where lower(username) = lower(btrim(target));
  if pid is null then raise exception 'Игрок % не найден', target; end if;
  select * into s from subscriptions where player_id = pid;

  if tariff = 'none' then
    delete from subscriptions where player_id = pid;
  elsif tariff = 'remove_beta' then
    update subscriptions set beta = false, updated_at = now(), updated_by = admin.username where player_id = pid;
  elsif tariff = 'beta' then
    if s.player_id is null or not _active(s) then
      raise exception 'Для беты нужна активная подписка';
    end if;
    update subscriptions set beta = true, updated_at = now(), updated_by = admin.username where player_id = pid;
  elsif tariff = 'lifetime' then
    insert into subscriptions (player_id, plan, expires_at, lifetime, updated_by)
    values (pid, 'lifetime', null, true, admin.username)
    on conflict (player_id) do update set plan = 'lifetime', expires_at = null, lifetime = true,
      updated_at = now(), updated_by = admin.username;
  else
    days := case tariff when '30d' then 30 when '180d' then 180 when '360d' then 360 end;
    if days is null then raise exception 'Неизвестный тариф %', tariff; end if;
    insert into subscriptions (player_id, plan, expires_at, lifetime, updated_by)
    values (pid, tariff, now() + make_interval(days => days), false, admin.username)
    on conflict (player_id) do update set
      plan = case when subscriptions.lifetime then subscriptions.plan else excluded.plan end,
      -- продлеваем от текущей даты окончания, если подписка ещё идёт
      expires_at = case when subscriptions.lifetime then null
        else greatest(coalesce(subscriptions.expires_at, now()), now()) + make_interval(days => days) end,
      updated_at = now(), updated_by = admin.username;
  end if;
end $$;

-- ---------- Права на функции ----------
revoke execute on function public._player(uuid), public._new_session(bigint) from public, anon, authenticated;
grant execute on function
  public.register(text, text), public.login(text, text), public.logout(uuid), public.me(uuid),
  public.online_players(uuid), public.chat_list(uuid, bigint), public.chat_send(uuid, text),
  public.chat_delete(uuid, bigint), public.admin_list_users(uuid, text),
  public.admin_set_subscription(uuid, text, text)
to anon, authenticated;
