-- 071 Idempotency keys for agents (Aaron, Nov 22, 2026: "continue until the system is ready"; Fable's review of Nov 21:
--   "No idempotency": a retried claim lost its one-time code). An agent or a page may send "Idempotency-Key" with any
--   write to /api/work/*. The first answer is kept for 24 hours, sealed under the key (only the sender has it), and a
--   repeat with the same key and the same request gets the same answer without doing the step again; the same key
--   with a different request is refused. Only answers that succeeded are kept: a refused step can be tried again.

set local role dog_owner;
create table app.idem_keys (
  id uuid primary key default app.uuid_v7(),
  scope_hash text not null unique check (char_length(scope_hash) = 64 and scope_hash ~ '^[0-9a-f]+$'),
  route text not null check (char_length(route) between 1 and 40),
  request_hash text not null check (char_length(request_hash) = 64 and request_hash ~ '^[0-9a-f]+$'),
  status smallint not null check (status between 200 and 299),
  sealed bytea not null check (octet_length(sealed) >= 29 and octet_length(sealed) <= 65536),
  created_at timestamptz not null default now()
);
create index idem_keys_created on app.idem_keys (created_at);
alter table app.idem_keys enable row level security;
alter table app.idem_keys force row level security;
create policy idem_keys_work on app.idem_keys for all to dog_work using (true) with check (true);
grant select, insert, delete on app.idem_keys to dog_work;
reset role;

grant create on schema app to dog_work;
set local role dog_work;
-- Before the step, in its transaction: wait for any other request with this key, then say what was kept, if anything.
create function app.idem_begin(p_scope text, p_route text, p_request text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare k record;
begin
  if p_scope is null or p_scope !~ '^[0-9a-f]{64}$' or p_request is null or p_request !~ '^[0-9a-f]{64}$' then raise exception 'bad idempotency key' using errcode = '22023'; end if;
  perform pg_advisory_xact_lock(hashtext('dayonegreat.idem ' || p_scope));
  delete from app.idem_keys x where x.created_at < now() - interval '24 hours';
  select * into k from app.idem_keys x where x.scope_hash = p_scope;
  if k.id is null then return jsonb_build_object('found', false); end if;
  if k.route <> p_route or k.request_hash <> p_request then return jsonb_build_object('found', true, 'mismatch', true); end if;
  return jsonb_build_object('found', true, 'mismatch', false, 'status', k.status, 'sealed', encode(k.sealed, 'base64'));
end $$;
-- After the step succeeded, in the same transaction: keep its answer, sealed.
create function app.idem_put(p_scope text, p_route text, p_request text, p_status integer, p_sealed bytea) returns void
language plpgsql security definer set search_path = pg_catalog as $$
begin
  insert into app.idem_keys (scope_hash, route, request_hash, status, sealed) values (p_scope, p_route, p_request, p_status, p_sealed)
    on conflict (scope_hash) do nothing;
end $$;
revoke execute on function app.idem_begin(text, text, text), app.idem_put(text, text, text, integer, bytea) from public;
grant execute on function app.idem_begin(text, text, text), app.idem_put(text, text, text, integer, bytea) to dog_app;
reset role;
revoke create on schema app from dog_work;
