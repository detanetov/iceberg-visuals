-- Iceberg Client: аватарки и смена пароля
alter table public.players add column if not exists avatar text;
alter table public.players add column if not exists avatar_updated_at timestamptz;

-- Мой профиль: добавлены avatar и avatar_v
drop function if exists public.me(uuid);
create function public.me(p_token uuid)
returns table (username text, is_admin boolean, plan text, expires_at timestamptz,
               lifetime boolean, beta boolean, active boolean, avatar text, avatar_v bigint)
language plpgsql security definer set search_path = public, extensions as $$
declare pl players; s subscriptions;
begin
  pl := _player(p_token);
  update players set last_seen = now() where id = pl.id;
  select * into s from subscriptions where player_id = pl.id;
  return query select pl.username, _is_admin(pl), s.plan, s.expires_at,
    coalesce(s.lifetime, false), coalesce(s.beta, false) and coalesce(_active(s), false),
    coalesce(_active(s), false), pl.avatar,
    coalesce(extract(epoch from pl.avatar_updated_at)::bigint, 0);
end $$;

-- Онлайн: добавлен avatar_v (версия аватарки, сама картинка — через get_avatars)
drop function if exists public.online_players(uuid);
create function public.online_players(p_token uuid)
returns table (username text, last_seen timestamptz, avatar_v bigint)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _player(p_token);
  return query select p.username, p.last_seen, coalesce(extract(epoch from p.avatar_updated_at)::bigint, 0)
    from players p where p.last_seen > now() - interval '2 minutes' order by lower(p.username);
end $$;

-- Чат: добавлен avatar_v автора
drop function if exists public.chat_list(uuid, bigint);
create function public.chat_list(p_token uuid, p_after bigint default 0)
returns table (id bigint, username text, body text, created_at timestamptz, avatar_v bigint)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _player(p_token);
  return query select * from (
    select m.id, m.username, m.body, m.created_at,
           coalesce(extract(epoch from p.avatar_updated_at)::bigint, 0)
    from messages m join players p on p.id = m.player_id
    where m.id > coalesce(p_after, 0) order by m.id desc limit 60
  ) t order by t.id;
end $$;

-- Картинки аватарок по списку ников
drop function if exists public.get_avatars(uuid, text[]);
create function public.get_avatars(p_token uuid, p_names text[])
returns table (username text, avatar text, avatar_v bigint)
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _player(p_token);
  return query select p.username, p.avatar, coalesce(extract(epoch from p.avatar_updated_at)::bigint, 0)
    from players p
    where lower(p.username) = any (select lower(x) from unnest(p_names[1:50]) x);
end $$;

-- Поставить или убрать аватарку (null — убрать)
drop function if exists public.set_avatar(uuid, text);
create function public.set_avatar(p_token uuid, p_avatar text) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare pl players; v timestamptz := now();
begin
  pl := _player(p_token);
  if p_avatar is not null then
    if p_avatar !~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$' then
      raise exception 'Аватарка должна быть картинкой PNG, JPEG или WebP';
    end if;
    if char_length(p_avatar) > 60000 then
      raise exception 'Картинка слишком большая';
    end if;
  end if;
  update players set avatar = p_avatar, avatar_updated_at = v where id = pl.id;
  return extract(epoch from v)::bigint;
end $$;

-- Сменить пароль (остальные сессии завершаются)
drop function if exists public.change_password(uuid, text, text);
create function public.change_password(p_token uuid, p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare pl players;
begin
  pl := _player(p_token);
  if pl.pass_hash <> crypt(coalesce(p_old, ''), pl.pass_hash) then
    perform pg_sleep(0.4);
    raise exception 'Текущий пароль неверный';
  end if;
  if char_length(coalesce(p_new, '')) < 6 then
    raise exception 'Новый пароль должен быть не короче 6 символов';
  end if;
  update players set pass_hash = crypt(p_new, gen_salt('bf', 8)) where id = pl.id;
  delete from sessions where player_id = pl.id and token <> p_token;
end $$;

grant execute on function
  public.me(uuid), public.online_players(uuid), public.chat_list(uuid, bigint),
  public.get_avatars(uuid, text[]), public.set_avatar(uuid, text),
  public.change_password(uuid, text, text)
to anon, authenticated;
