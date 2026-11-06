-- 037 Sign-in with a browser key and a PIN (Aaron, Nov 5, 2026: "Use our auth system we currently have. Allow various
--   file types. But don't weaken security." and his diagram of the three ways in; harness/FACTS.md).
--   Every way in now needs two things, and all three end at the same check in this database:
--     1. First time, or a lost key file: the code posted through giscus, claimed by the JEVs gate for the GitHub account
--        that posted it (023 and 028, unchanged), then a new six-digit PIN (app.code_sign_in_pin).
--     2. A new browser: the key file and the PIN, with no post (app.file_sign_in_pin). The member gets an in-app notice,
--        "New browser added".
--     3. This browser again: the PIN alone, with this browser's key (app.browser_sign_in).
--   The browser key: the browser makes an ECDSA P-256 key pair with Web Crypto, its private key marked non-extractable
--   and kept in that site's IndexedDB, so no script can read it out and no other site (a look-alike included) can use
--   it. Only its public key is stored here (app.browser_keys). Each sign-in asks this database for a one-time challenge,
--   good for 2 minutes, made for this site's own address (app.signin_challenge); the browser signs the challenge and
--   that address together, and the challenge is used up by the first try, right or wrong. The signature is checked
--   here, by app.p256_verify below, not only by the site, so the site's own database login can't sign anyone in
--   through the browser lane without that browser's key (the same line 025 drew for the administrator).
--   The PIN: never stored as typed. A SHA-256 keyed with a key made here (app.pin_keys, as 019's app.actor_keys: only
--   the sign-in role reads it, through these functions) over a random salt, the member's ID and the PIN. A copy of the
--   tables taken through the site's or the gate's login holds no PIN and no key to test PINs with. A copy of the whole
--   database, key table included, could test all million PINs at once; no hash can stop that for six digits, so the
--   limit that matters is the count: each browser key, and the key file, allows 10 wrong PINs. The 5th alerts Aaron and
--   tells the member in-app; the 10th cancels that browser key (or the key file), which is then added again through
--   lane 1 or 2. Lane 1 (GitHub) never counts PINs and is never closed, so nobody is locked out of their account
--   (Aaron's standing rule: checks alert, never lock out). PINs anyone would try first (one digit repeated, runs, short
--   patterns repeated) are refused when set.
--   Members who signed up before this have a key file and no PIN. Their next sign-in by either of today's ways sets their
--   PIN and gives that browser its key: lane 1 as for everyone; lane 2 with the right key file and no PIN yet takes the
--   PIN typed as the new one. That one sign-in is exactly as strong as today's key-file sign-in; from then on the file
--   alone no longer signs in.
--   The site can no longer call the two sign-ins without a PIN (023's app.code_sign_in, 030's app.file_sign_in): only
--   the new functions reach them, so no way in skips the check. Sessions already issued are untouched. "Sign out
--   everywhere" now cancels every browser key as well as the key file.
set local role dog_owner;

-- ---- The PIN key: 32 random bytes made here, read only by the sign-in role (as 019's app.actor_keys) ----
create table app.pin_keys (
  id uuid primary key default app.uuid_v7(),
  singleton boolean not null default true unique check (singleton),
  pin_key bytea not null check (octet_length(pin_key) = 32)
);
alter table app.pin_keys enable row level security;
alter table app.pin_keys force row level security;
create policy pin_keys_signin on app.pin_keys for select to dog_signin using (true);
create policy pin_keys_owner_insert on app.pin_keys for insert to dog_owner with check (true);
grant select on app.pin_keys to dog_signin;
-- 32 bytes from two random UUIDs (244 random bits), with Postgres's own generator, as in 019.
insert into app.pin_keys (pin_key) values (decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex'));

-- ---- Each member's PIN ----
create table app.signin_pins (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null unique references app.members (id) on delete cascade,
  salt bytea not null check (octet_length(salt) = 16),
  pin_hash bytea not null check (octet_length(pin_hash) = 32),
  -- Wrong current PINs typed on the account page's "Change your PIN" since the last right one; at 10 that session ends.
  change_failed smallint not null default 0 check (change_failed between 0 and 10),
  set_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table app.signin_pins enable row level security;
alter table app.signin_pins force row level security;
create policy signin_pins_signin_select on app.signin_pins for select to dog_signin using (true);
create policy signin_pins_signin_insert on app.signin_pins for insert to dog_signin with check (true);
create policy signin_pins_signin_update on app.signin_pins for update to dog_signin using (true) with check (true);
create policy signin_pins_signin_delete on app.signin_pins for delete to dog_signin using (true);
grant select, delete on app.signin_pins to dog_signin;
grant insert (member_id, salt, pin_hash) on app.signin_pins to dog_signin;
grant update (salt, pin_hash, change_failed, set_at) on app.signin_pins to dog_signin;

-- ---- Each browser's public key ----
create table app.browser_keys (
  id uuid primary key default app.uuid_v7(),
  member_id uuid not null references app.members (id) on delete cascade,
  -- The raw uncompressed P-256 point (0x04, X, Y), checked to be on the curve when it is added.
  public_key bytea not null unique check (octet_length(public_key) = 65),
  -- The browser's own short name for itself, from a fixed list ("Firefox on Linux"), so the member can tell their
  -- browsers apart on the account page. Never the full browser details.
  label text not null check (char_length(label) <= 40 and label ~ '^[A-Za-z ]+$'),
  -- Wrong PINs with this browser since its last sign-in; at 10 it is cancelled (the row is deleted).
  failed smallint not null default 0 check (failed between 0 and 10),
  created_at timestamptz not null default now(),
  used_at timestamptz
);
create index browser_keys_member on app.browser_keys (member_id);
alter table app.browser_keys enable row level security;
alter table app.browser_keys force row level security;
create policy browser_keys_signin_select on app.browser_keys for select to dog_signin using (true);
create policy browser_keys_signin_insert on app.browser_keys for insert to dog_signin with check (true);
create policy browser_keys_signin_update on app.browser_keys for update to dog_signin using (true) with check (true);
create policy browser_keys_signin_delete on app.browser_keys for delete to dog_signin using (true);
grant select, delete on app.browser_keys to dog_signin;
grant insert (member_id, public_key, label) on app.browser_keys to dog_signin;
grant update (failed, used_at) on app.browser_keys to dog_signin;

-- ---- One-time challenges ----
create table app.signin_challenges (
  id uuid primary key default app.uuid_v7(),
  -- Only the challenge's SHA-256: the challenge itself goes to the browser once.
  challenge_hash text not null unique check (char_length(challenge_hash) = 64 and challenge_hash ~ '^[0-9a-f]+$'),
  -- The site's own address it was made for (signin/config.js ORIGIN), signed with it.
  origin text not null check (char_length(origin) <= 100 and origin ~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?$'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);
create index signin_challenges_expires on app.signin_challenges (expires_at);
alter table app.signin_challenges enable row level security;
alter table app.signin_challenges force row level security;
create policy signin_challenges_signin_select on app.signin_challenges for select to dog_signin using (true);
create policy signin_challenges_signin_insert on app.signin_challenges for insert to dog_signin with check (true);
create policy signin_challenges_signin_update on app.signin_challenges for update to dog_signin using (true) with check (true);
create policy signin_challenges_signin_delete on app.signin_challenges for delete to dog_signin using (true);
grant select, delete on app.signin_challenges to dog_signin;
grant insert (challenge_hash, origin, expires_at) on app.signin_challenges to dog_signin;
grant update (used_at) on app.signin_challenges to dog_signin;

-- The key file counts wrong PINs tried with it, apart from wrong files (023's failed).
alter table app.file_keys add column pin_failed smallint not null default 0 check (pin_failed between 0 and 10);
-- Aaron (Nov 5): 3 wrong key files pause key-file sign-in for that username for 10 minutes (app.file_sign_in_pin).
alter table app.file_keys add column paused_until timestamptz;
alter table app.file_keys add column last_paused_at timestamptz;
grant update (pin_failed, paused_until, last_paused_at) on app.file_keys to dog_signin;

-- ---- Notices: the member's PIN and browsers ----
alter table app.notices drop constraint notices_kind_check;
alter table app.notices add constraint notices_kind_check check (kind = any (array['draft_waiting', 'draft_expired', 'report_upheld', 'brake_on',
  'contained', 'containment_lifted', 'appeal_decided', 'act_reconfirm', 'act_expired', 'challenge', 'account_flagged', 'alert',
  'signin_linked', 'signin_unlinked', 'signin_keyfile', 'post_published', 'signin_pin', 'signin_browser']));
drop policy notices_signin_insert on app.notices;
create policy notices_signin_insert on app.notices for insert to dog_signin
  with check ((member_id is not null and kind in ('signin_linked', 'signin_unlinked', 'signin_keyfile', 'signin_pin', 'signin_browser'))
              or (member_id is null and kind = 'alert' and (dedupe_key like 'signin:capped:%' or dedupe_key like 'watch:%')));

-- ---- ECDSA P-256 with SHA-256, checked here ----
-- Verification only: every input is public (a public key, a challenge, a signature), so nothing secret can leak
-- through timing. Plain arithmetic on numeric, in Jacobian coordinates; the curve is NIST P-256 (FIPS 186-5, SEC 2).
-- test/signin-pin.test.js checks it against Node's own crypto on hundreds of random keys, messages and signatures,
-- with every single-bit change refused, and on the edge cases (r or s zero or too large, a point off the curve).
create function app.p256_int(b bytea) returns numeric
language plpgsql immutable strict set search_path = pg_catalog as $$
declare n numeric := 0; i integer;
begin
  for i in 0 .. length(b) - 1 loop n := n * 256 + get_byte(b, i); end loop;
  return n;
end $$;

create function app.p256_powmod(b numeric, e numeric, m numeric) returns numeric
language plpgsql immutable strict set search_path = pg_catalog as $$
declare r numeric := 1; x numeric := mod(b, m); k numeric := e;
begin
  while k > 0 loop
    if mod(k, 2) = 1 then r := mod(r * x, m); end if;
    x := mod(x * x, m);
    k := div(k, 2);
  end loop;
  return r;
end $$;

-- Doubling, for a = -3 ("dbl-2001-b"). Z = 0 is the point at infinity.
create function app.p256_double(x numeric, y numeric, z numeric, out rx numeric, out ry numeric, out rz numeric)
language plpgsql immutable strict set search_path = pg_catalog as $$
declare p constant numeric := 115792089210356248762697446949407573530086143415290314195533631308867097853951;
  d numeric; g numeric; b numeric; a numeric;
begin
  if z = 0 or y = 0 then rx := 0; ry := 1; rz := 0; return; end if;
  d := mod(z * z, p);
  g := mod(y * y, p);
  b := mod(x * g, p);
  a := mod(3 * (x - d) * (x + d), p); if a < 0 then a := a + p; end if;
  rx := mod(a * a - 8 * b, p); if rx < 0 then rx := rx + p; end if;
  rz := mod((y + z) * (y + z) - g - d, p); if rz < 0 then rz := rz + p; end if;
  ry := mod(a * (4 * b - rx) - 8 * g * g, p); if ry < 0 then ry := ry + p; end if;
end $$;

-- Addition ("add-2007-bl"), with the point at infinity, equal points and opposite points handled.
create function app.p256_add(x1 numeric, y1 numeric, z1 numeric, x2 numeric, y2 numeric, z2 numeric,
                             out rx numeric, out ry numeric, out rz numeric)
language plpgsql immutable strict set search_path = pg_catalog as $$
declare p constant numeric := 115792089210356248762697446949407573530086143415290314195533631308867097853951;
  z1z1 numeric; z2z2 numeric; u1 numeric; u2 numeric; s1 numeric; s2 numeric; h numeric; r numeric; hh numeric; hhh numeric; v numeric;
begin
  if z1 = 0 then rx := x2; ry := y2; rz := z2; return; end if;
  if z2 = 0 then rx := x1; ry := y1; rz := z1; return; end if;
  z1z1 := mod(z1 * z1, p); z2z2 := mod(z2 * z2, p);
  u1 := mod(x1 * z2z2, p); u2 := mod(x2 * z1z1, p);
  s1 := mod(y1 * z2 * z2z2, p); s2 := mod(y2 * z1 * z1z1, p);
  h := mod(u2 - u1 + p, p); r := mod(s2 - s1 + p, p);
  if h = 0 then
    if r = 0 then select d.rx, d.ry, d.rz into rx, ry, rz from app.p256_double(x1, y1, z1) d; return; end if;
    rx := 0; ry := 1; rz := 0; return;
  end if;
  hh := mod(h * h, p); hhh := mod(h * hh, p); v := mod(u1 * hh, p);
  rx := mod(mod(r * r - hhh - 2 * v, p) + p, p);
  ry := mod(mod(r * (v - rx) - s1 * hhh, p) + p, p);
  rz := mod(z1 * z2 * h, p);
end $$;

-- Whether a raw uncompressed public key (0x04 || X || Y) is a point on P-256. The cofactor is 1, so on the curve and
-- not the point at infinity (which has no such encoding) is enough.
create function app.p256_point_ok(pub bytea) returns boolean
language plpgsql immutable set search_path = pg_catalog as $$
declare p constant numeric := 115792089210356248762697446949407573530086143415290314195533631308867097853951;
  b constant numeric := 41058363725152142129326129780047268409114441015993725554835256314039467401291;
  x numeric; y numeric;
begin
  if pub is null or length(pub) <> 65 or get_byte(pub, 0) <> 4 then return false; end if;
  x := app.p256_int(substring(pub from 2 for 32)); y := app.p256_int(substring(pub from 34 for 32));
  if x >= p or y >= p then return false; end if;
  return mod(y * y, p) = mod(mod(x * x * x, p) - 3 * x + b + 3 * p, p);
end $$;

-- ECDSA P-256 with SHA-256 over msg; sig is r || s, 64 bytes, as Web Crypto gives it.
create function app.p256_verify(pub bytea, msg bytea, sig bytea) returns boolean
language plpgsql immutable set search_path = pg_catalog as $$
declare p constant numeric := 115792089210356248762697446949407573530086143415290314195533631308867097853951;
  n constant numeric := 115792089210356248762697446949407573529996955224135760342422259061068512044369;
  gx constant numeric := 48439561293906451759052585252797914202762949526041747995844080717082404635286;
  gy constant numeric := 36134250956749795798585127919587881956611106672985015071877198253568414405109;
  qx numeric; qy numeric; r numeric; s numeric; e numeric; w numeric; u1 numeric; u2 numeric;
  sx numeric; sy numeric; sz numeric; ax numeric; ay numeric; az numeric; i integer; b1 boolean; b2 boolean; zz numeric; bit numeric;
begin
  if msg is null or sig is null or length(sig) <> 64 or not app.p256_point_ok(pub) then return false; end if;
  qx := app.p256_int(substring(pub from 2 for 32)); qy := app.p256_int(substring(pub from 34 for 32));
  r := app.p256_int(substring(sig from 1 for 32)); s := app.p256_int(substring(sig from 33 for 32));
  if r < 1 or r >= n or s < 1 or s >= n then return false; end if;
  e := app.p256_int(sha256(msg)); -- the hash is 256 bits, the size of n: nothing to cut
  w := app.p256_powmod(s, n - 2, n); -- s^-1 mod n (n is prime)
  u1 := mod(e * w, n); u2 := mod(r * w, n);
  -- u1·G + u2·Q in one pass (Shamir's trick), with G + Q made first.
  select t.rx, t.ry, t.rz into sx, sy, sz from app.p256_add(gx, gy, 1, qx, qy, 1) t;
  ax := 0; ay := 1; az := 0;
  for i in reverse 255 .. 0 loop
    select t.rx, t.ry, t.rz into ax, ay, az from app.p256_double(ax, ay, az) t;
    bit := power(2::numeric, i);
    b1 := mod(div(u1, bit), 2) = 1;
    b2 := mod(div(u2, bit), 2) = 1;
    if b1 and b2 then select t.rx, t.ry, t.rz into ax, ay, az from app.p256_add(ax, ay, az, sx, sy, sz) t;
    elsif b1 then select t.rx, t.ry, t.rz into ax, ay, az from app.p256_add(ax, ay, az, gx, gy, 1) t;
    elsif b2 then select t.rx, t.ry, t.rz into ax, ay, az from app.p256_add(ax, ay, az, qx, qy, 1) t;
    end if;
  end loop;
  if az = 0 then return false; end if;
  -- x(R) mod n = r, without an inversion: x = X / Z^2, and x is r or r + n (only when r + n < p).
  zz := mod(az * az, p);
  if mod(r * zz, p) = ax then return true; end if;
  return r + n < p and mod((r + n) * zz, p) = ax;
end $$;

-- What the browser signs: a fixed label, the site's address and the challenge, one per line (UTF-8).
create function app.signin_message(p_origin text, p_challenge text) returns bytea
language sql immutable set search_path = pg_catalog as $$
  select convert_to('dayonegreat-signin-v1' || chr(10) || p_origin || chr(10) || p_challenge, 'UTF8')
$$;

-- A PIN anyone would try first: one digit six times, a run up or down, or a short pattern repeated, and a few more
-- that lists of common PINs put near the top. Refused when a PIN is set (on the site too, so people are told why).
create function app.pin_weak(p text) returns boolean
language plpgsql immutable set search_path = pg_catalog as $$
declare i integer; up boolean := true; down boolean := true;
begin
  if p is null or p !~ '^[0-9]{6}$' then return true; end if;
  for i in 1 .. 5 loop
    if (substr(p, i + 1, 1)::int - substr(p, i, 1)::int + 10) % 10 <> 1 then up := false; end if;
    if (substr(p, i, 1)::int - substr(p, i + 1, 1)::int + 10) % 10 <> 1 then down := false; end if;
  end loop;
  return up or down or p = repeat(substr(p, 1, 1), 6) or p = repeat(substr(p, 1, 2), 3) or p = repeat(substr(p, 1, 3), 2)
    or p = any (array['112233', '123321', '159753', '147258', '147852', '258456', '789456', '102030', '159357', '753951', '852456', '000123']);
end $$;

-- Who may call the helpers: the sign-in role, from inside its own functions below. They are dog_owner's, and don't run
-- with anyone's rights but the caller's.
revoke execute on function app.p256_int(bytea), app.p256_powmod(numeric, numeric, numeric),
  app.p256_double(numeric, numeric, numeric), app.p256_add(numeric, numeric, numeric, numeric, numeric, numeric),
  app.p256_point_ok(bytea), app.p256_verify(bytea, bytea, bytea), app.signin_message(text, text), app.pin_weak(text) from public;
grant execute on function app.p256_int(bytea), app.p256_powmod(numeric, numeric, numeric),
  app.p256_double(numeric, numeric, numeric), app.p256_add(numeric, numeric, numeric, numeric, numeric, numeric),
  app.p256_point_ok(bytea), app.p256_verify(bytea, bytea, bytea), app.signin_message(text, text), app.pin_weak(text) to dog_signin;

-- ---- The sign-in role's own steps (called by nobody else) ----

-- The keyed hash of a PIN for a member, with their salt.
create function app.pin_digest(p_member uuid, p_salt bytea, p_pin text) returns bytea
language sql stable security definer set search_path = pg_catalog as $$
  select sha256(k.pin_key || p_salt || convert_to(p_member::text || ':' || p_pin, 'UTF8') || k.pin_key)
  from app.pin_keys k where k.singleton
$$;

-- Sets (or replaces) a member's PIN, with a new salt. True if a PIN was replaced.
create function app.pin_store(p_member uuid, p_pin text) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare salt bytea := substring(decode(replace(gen_random_uuid()::text, '-', ''), 'hex') from 1 for 16);
  had boolean;
begin
  if p_member is null or p_pin is null or p_pin !~ '^[0-9]{6}$' or app.pin_weak(p_pin) then
    raise exception 'weak_pin' using errcode = 'P0001';
  end if;
  had := exists (select 1 from app.signin_pins x where x.member_id = p_member);
  insert into app.signin_pins (member_id, salt, pin_hash) values (p_member, salt, app.pin_digest(p_member, salt, p_pin))
    on conflict (member_id) do update set salt = excluded.salt, pin_hash = excluded.pin_hash, change_failed = 0, set_at = now();
  return had;
end $$;

-- Whether this is the member's PIN (false when they have none).
create function app.pin_matches(p_member uuid, p_pin text) returns boolean
language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select x.pin_hash = app.pin_digest(p_member, x.salt, p_pin) from app.signin_pins x
                   where x.member_id = p_member and p_pin ~ '^[0-9]{6}$'), false)
$$;

-- The browser's proof: the challenge is this site's, unused and not expired, and the browser's key signed it with this
-- site's address. The challenge is used up whatever the answer, so it never works twice.
create function app.signin_proof(p_public bytea, p_challenge text, p_origin text, p_signature bytea) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare ch app.signin_challenges%rowtype;
begin
  if p_challenge is null or p_challenge !~ '^[A-Za-z0-9_-]{43}$' or p_origin is null then
    return false;
  end if;
  update app.signin_challenges c set used_at = now()
    where c.challenge_hash = encode(sha256(convert_to(p_challenge, 'UTF8')), 'hex') and c.used_at is null and c.expires_at > now()
    returning * into ch;
  if not found or ch.origin is distinct from p_origin then
    return false;
  end if;
  return app.p256_verify(p_public, app.signin_message(ch.origin, p_challenge), p_signature);
end $$;

-- Keeps this browser's public key for the member, at most 20 per member (the one used longest ago goes first).
create function app.browser_key_add(p_member uuid, p_public bytea, p_label text) returns uuid
language plpgsql security definer set search_path = pg_catalog as $$
declare kid uuid;
begin
  if p_label is null or p_label !~ '^[A-Za-z ]{3,40}$' or not app.p256_point_ok(p_public) then
    raise exception 'bad browser key' using errcode = '22023';
  end if;
  delete from app.browser_keys b where b.id in (select x.id from app.browser_keys x where x.member_id = p_member
    order by coalesce(x.used_at, x.created_at) desc offset 19);
  insert into app.browser_keys (member_id, public_key, label) values (p_member, p_public, p_label) returning id into kid;
  return kid;
end $$;

-- A wrong PIN against one credential: a browser key ('browser'), the key file ('file') or the account page's "Change
-- your PIN" ('change'). The 5th tells Aaron and the member (again on a later day, if it happens again); the 10th, for a
-- browser key or the key file, tells both that it was cancelled (the caller deletes it). The alerts never stop the count
-- or the cancellation.
create function app.pin_wrong(p_member uuid, p_kind text, p_id uuid, p_count integer) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare what text := case p_kind when 'browser' then 'this browser' when 'file' then 'your key file' else 'your account page' end;
  thing text := case p_kind when 'browser' then 'browser key' when 'file' then 'key file' else 'PIN change form' end;
  adm boolean := exists (select 1 from app.members m where m.id = p_member and m.is_admin);
  day text := to_char(now() at time zone 'UTC', 'YYYYMMDD');
begin
  if p_count = 5 then
    begin
      perform app.notify(null, 'alert', case when adm then 'Wrong PINs on your own account' else 'Wrong PINs for one account' end,
        '5 wrong PINs have been tried with one member''s ' || thing || '. At 10 '
        || case when p_kind = 'change' then 'that session is signed out' else 'it is cancelled' end
        || '; their GitHub sign-in always stays open.', '/controls', 'member', p_member,
        'watch:pin5:' || p_kind || ':' || p_id::text || ':' || day);
    exception when others then null;
    end;
    perform app.notify(p_member, 'signin_pin', 'Wrong PINs were tried',
      '5 wrong PINs have been tried with ' || what || '. If that wasn''t you, sign out everywhere from your account page. '
      || case when p_kind = 'change' then 'After 10, that session is signed out.'
              else 'After 10, ' || what || ' is cancelled; you can always sign in again with GitHub on the join page.' end,
      '/account', 'member', p_member, 'signin:pin5:' || p_kind || ':' || p_id::text || ':' || day);
  elsif p_count >= 10 and p_kind in ('browser', 'file') then
    begin
      perform app.notify(null, 'alert', case when adm then 'Your own ' || thing || ' was cancelled' else 'A member''s ' || thing || ' was cancelled' end,
        '10 wrong PINs were tried, so it no longer signs in. The account is safe; the member signs in again with GitHub, or a '
        || 'new browser with their key file and PIN.', '/controls', 'member', p_member, 'watch:pin10:' || p_kind || ':' || p_id::text);
    exception when others then null;
    end;
    perform app.notify(p_member, 'signin_pin', case when p_kind = 'browser' then 'A browser of yours was cancelled' else 'Your key file was cancelled' end,
      '10 wrong PINs were tried with ' || what || ', so it no longer signs you in. Your account is safe. To sign in, get a '
      || 'new code on the join page' || case when p_kind = 'browser' then ', or use your key file and PIN' else '' end || '.', '/join',
      'member', p_member, 'signin:pin10:' || p_kind || ':' || p_id::text);
  end if;
end $$;

-- ---- The three ways in, for the site's role ----

-- A new one-time challenge for this site's address, good for 2 minutes. Clears challenges more than an hour old.
create function app.signin_challenge(p_origin text) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare v text := translate(encode(decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex'), 'base64'), '+/=', '-_');
begin
  if p_origin is null or char_length(p_origin) > 100 or p_origin !~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?$' or app.actor_kind() <> 'anon' then
    raise exception 'bad challenge request' using errcode = '22023';
  end if;
  delete from app.signin_challenges c where c.expires_at < now() - interval '1 hour';
  insert into app.signin_challenges (challenge_hash, origin, expires_at)
    values (encode(sha256(convert_to(v, 'UTF8')), 'hex'), p_origin, now() + interval '2 minutes');
  return v;
end $$;

-- Lane 1's waiting step, asked every 2 seconds by /join: has the gate claimed this browser's code yet? 'waiting',
-- 'claimed' (with the seconds the code has left to finish in) or 'expired'. Changes nothing. Once claimed, for the
-- account that claimed it (the person's own, proved by GitHub): whether it has a PIN already and how many browsers, so
-- the "Set your PIN" step can offer to remove the other browsers (the review of 037, L2).
create function app.code_status(p_browser_hash text, out status text, out seconds_left integer, out has_pin boolean, out browsers integer)
language plpgsql stable security definer set search_path = pg_catalog as $$
declare c app.code_signins%rowtype; mid uuid;
begin
  if p_browser_hash is null or p_browser_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad code request' using errcode = '22023';
  end if;
  select * into c from app.code_signins x where x.browser_hash = p_browser_hash and x.status in ('waiting', 'claimed')
    and x.expires_at > now() order by (x.status = 'claimed') desc, x.created_at desc limit 1;
  if not found then status := 'expired'; seconds_left := 0; return; end if;
  status := c.status;
  seconds_left := greatest(0, floor(extract(epoch from c.expires_at - now()))::integer);
  if c.status = 'claimed' then
    select i.member_id into mid from app.identities i where i.provider = 'github' and i.fingerprint = c.fingerprint;
    has_pin := mid is not null and exists (select 1 from app.signin_pins x where x.member_id = mid);
    browsers := case when mid is null then 0 else (select count(*)::integer from app.browser_keys b where b.member_id = mid) end;
  end if;
end $$;

-- The public half of one browser's key, by its ID, so the site checks the signature itself with Node's crypto before
-- the database checks it again (the review of 037, M2). Null for a key that isn't there. Nothing secret: a public key.
create function app.browser_key_public(p_key_id uuid) returns bytea
language sql stable security definer set search_path = pg_catalog as $$
  select b.public_key from app.browser_keys b where b.id = p_key_id
$$;

-- A refusal raised by the sign-in itself (a banned or disabled account, a region, a browser key that isn't well made),
-- as the status each lane returns. Each lane catches it in a block of its own, so what came before it (the challenge used
-- up, a wrong-PIN count) is kept when the sign-in is refused (the review of 037, L1).
create function app.signin_refusal(p_state text, p_message text) returns text
language sql immutable set search_path = pg_catalog as $$
  select case when p_state = 'P0001' and p_message in ('banned', 'disabled', 'taken', 'region', 'weak_pin') then p_message
              when p_state in ('22023', '23505') then 'bad_key' end
$$;
revoke execute on function app.signin_refusal(text, text) from public;
grant execute on function app.signin_refusal(text, text) to dog_signin;

-- Lane 1: the claimed code (028's app.code_sign_in, unchanged, with the JEVs gate's claim and the founder's
-- promotion), then the member's new PIN and this browser's key. The browser's proof comes first. p_remove_others (L2):
-- when a PIN is replaced, the member's other browsers can be removed in the same step, so none of them gets 10 tries at
-- the new PIN.
create function app.code_sign_in_pin(p_browser_hash text, p_display_name text, p_session_hash text, p_session_days integer,
  p_region text, p_pin text, p_public bytea, p_label text, p_challenge text, p_origin text, p_signature bytea, p_remove_others boolean)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, key_id uuid)
language plpgsql security definer set search_path = pg_catalog as $$
declare s record; replaced boolean; kid uuid; why text; gone integer := 0;
begin
  if p_pin is null or p_pin !~ '^[0-9]{6}$' or app.pin_weak(p_pin) then
    return query select 'weak_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end if;
  if not app.signin_proof(p_public, p_challenge, p_origin, p_signature) then
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end if;
  begin
    select * into s from app.code_sign_in(p_browser_hash, p_display_name, p_session_hash, p_session_days, p_region) x;
    if s.status <> 'ok' then
      return query select s.status, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
    end if;
    replaced := app.pin_store(s.member_id, p_pin);
    kid := app.browser_key_add(s.member_id, p_public, p_label);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid; return;
  end;
  if replaced and coalesce(p_remove_others, false) then
    delete from app.browser_keys b where b.member_id = s.member_id and b.id <> kid;
    get diagnostics gone = row_count;
  end if;
  if replaced then
    perform app.notify(s.member_id, 'signin_pin', 'Your PIN was changed',
      'Your PIN was set again when you signed in with a code posted through GitHub'
      || case when gone > 0 then ', and your other browsers (' || gone || ') were removed' else '' end
      || '. If that wasn''t you, sign out everywhere from your account page.', '/account', 'member', s.member_id,
      'signin:pinset:' || p_session_hash);
  end if;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, kid;
end $$;

-- Lane 2: the key file and the PIN on a new browser, then the notice "New browser added". Aaron (Nov 5): "Send an
-- in-app notification from the user to notify them that 3 failed logins in and lock account for 10 min before before
-- allowing access again." The 3rd wrong key file for a username leaves the member an in-app notice and pauses this
-- lane, for that username only, for 10 minutes: no file is tested while it is paused, and it then works again. Wrong
-- files no longer cancel the key file; 10 wrong PINs with the right file still do (his diagram). The member's own
-- browser (lane 3) and GitHub (lane 1) stay open, so a stranger who knows a username can't shut the member out (his
-- standing rule: checks alert, never lock out). A member with no PIN yet (an account from before 037) sets it here,
-- typed twice (L3).
create function app.file_sign_in_pin(p_login_hash text, p_key_hash text, p_display_name text, p_session_hash text,
  p_session_days integer, p_region text, p_pin text, p_public bytea, p_label text, p_challenge text, p_origin text, p_signature bytea,
  p_pin_again text)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, key_id uuid, tries_left smallint, wait_seconds integer)
language plpgsql security definer set search_path = pg_catalog as $$
declare k app.file_keys%rowtype; s record; kid uuid; first_pin boolean; why text;
begin
  if p_login_hash is null or p_login_hash !~ '^[0-9a-f]{64}$' or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'bad key file request' using errcode = '22023';
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  if not app.signin_proof(p_public, p_challenge, p_origin, p_signature) then
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  select * into k from app.file_keys f where f.login_hash = p_login_hash for update;
  if found and k.paused_until > now() then
    return query select 'paused'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint,
      greatest(1, ceil(extract(epoch from k.paused_until - now()))::integer); return;
  end if;
  if not found or k.key_hash <> p_key_hash then
    if found then
      update app.file_keys f set failed = f.failed + 1 where f.id = k.id returning * into k;
      if k.failed >= 3 then
        update app.file_keys f set failed = 0, paused_until = now() + interval '10 minutes', last_paused_at = now() where f.id = k.id;
        begin
          perform app.notify(null, 'alert', case when exists (select 1 from app.members m where m.id = k.member_id and m.is_admin)
              then 'Key-file sign-in paused on your own account' else 'Key-file sign-in paused for one account' end,
            '3 wrong key files were tried for one member''s GitHub username, so signing in with a key file is paused for that '
            || 'username for 10 minutes. Their browser and their GitHub sign-in still work.', '/controls', 'member', k.member_id,
            'watch:paused:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
        exception when others then null;
        end;
        perform app.notify(k.member_id, 'signin_keyfile', 'Key-file sign-in paused for 10 minutes',
          '3 wrong key files were tried with your GitHub username, so signing in with your key file is paused for 10 minutes; '
          || 'then it works again. Your account is safe. This browser, with your PIN, and a new code on the join page still sign '
          || 'you in. If it wasn''t you, you don''t need to do anything.', '/account', 'member', k.member_id,
          'signin:keyfile:paused:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
        return query select 'paused'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, 600; return;
      end if;
    end if;
    return query select 'no_match'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end if;
  -- The right file. Its PIN, or (an account from before 037) the PIN it sets now, typed twice.
  first_pin := not exists (select 1 from app.signin_pins x where x.member_id = k.member_id);
  if first_pin then
    if app.pin_weak(p_pin) then
      return query select 'weak_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
    if p_pin_again is distinct from p_pin then
      return query select 'confirm_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
    end if;
  elsif not app.pin_matches(k.member_id, p_pin) then
    update app.file_keys f set pin_failed = least(f.pin_failed + 1, 10) where f.id = k.id returning * into k;
    perform app.pin_wrong(k.member_id, 'file', k.id, k.pin_failed);
    if k.pin_failed >= 10 then
      delete from app.file_keys f where f.id = k.id;
      return query select 'start_again'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, 0::smallint, null::integer; return;
    end if;
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, (10 - k.pin_failed)::smallint, null::integer; return;
  end if;
  begin
    select * into s from app.sign_in_core('github', array[k.fingerprint], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
    if first_pin then
      perform app.pin_store(s.member_id, p_pin);
    end if;
    kid := app.browser_key_add(s.member_id, p_public, p_label);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::uuid, null::smallint, null::integer; return;
  end;
  -- 030's alert: the right key file after wrong ones for the username (since the review of 037, after a pause in the
  -- last day too). All of it inside the catch.
  begin
    if k.failed >= coalesce((select w.wrong_files_before from app.watch_settings w limit 1), 3) or k.last_paused_at > now() - interval '1 day' then
      perform app.notify(null, 'alert', 'A sign-in after wrong key files',
        'The right key file signed in after wrong ones were tried for the same GitHub username. If the wrong ones weren''t '
        || 'the member''s own mistakes, someone else has been trying their username.', '/controls',
        'member', k.member_id, 'watch:afterfail:' || k.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDD'));
    end if;
  exception when others then null;
  end;
  update app.file_keys f set used_at = now(), failed = 0, pin_failed = 0 where f.id = k.id;
  perform app.notify(s.member_id, 'signin_browser', 'New browser added',
    'Your key file and PIN added a new browser (' || p_label || ') and signed it in. If that wasn''t you, remove it on your '
    || 'account page and sign out everywhere.', '/account', 'member', s.member_id, 'signin:browser:' || kid::text);
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, kid, null::smallint, null::integer;
end $$;

-- Lane 3: this browser again, with its key and the PIN. A wrong PIN counts against this browser's key.
create function app.browser_sign_in(p_key_id uuid, p_display_name text, p_session_hash text, p_session_days integer,
  p_region text, p_pin text, p_challenge text, p_origin text, p_signature bytea)
returns table (status text, member_id uuid, is_new boolean, trust_level smallint, is_admin boolean, tries_left smallint)
language plpgsql security definer set search_path = pg_catalog as $$
declare b app.browser_keys%rowtype; s record; fp text; why text;
begin
  select * into b from app.browser_keys x where x.id = p_key_id for update;
  if not found then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  -- The proof first: without this browser's private key, no PIN is ever tested.
  if not app.signin_proof(b.public_key, p_challenge, p_origin, p_signature) then
    return query select 'bad_proof'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  if not app.pin_matches(b.member_id, p_pin) then
    if not exists (select 1 from app.signin_pins x where x.member_id = b.member_id) then
      return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
    end if;
    update app.browser_keys x set failed = least(x.failed + 1, 10) where x.id = b.id returning * into b;
    perform app.pin_wrong(b.member_id, 'browser', b.id, b.failed);
    if b.failed >= 10 then
      delete from app.browser_keys x where x.id = b.id;
      return query select 'cancelled'::text, null::uuid, null::boolean, null::smallint, null::boolean, 0::smallint; return;
    end if;
    return query select 'wrong_pin'::text, null::uuid, null::boolean, null::smallint, null::boolean, (10 - b.failed)::smallint; return;
  end if;
  -- The member's GitHub sign-in method, the one their account began with (never a fingerprint the caller names).
  select i.fingerprint into fp from app.identities i where i.member_id = b.member_id and i.provider = 'github'
    order by (i.linked_by is null) desc, i.created_at limit 1;
  if fp is null then
    return query select 'no_key'::text, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end if;
  begin
    select * into s from app.sign_in_core('github', array[fp], 1::smallint, 1::smallint, p_display_name,
                                     p_session_hash, p_session_days, null::timestamptz, null::uuid, p_region);
  exception when sqlstate 'P0001' or sqlstate '22023' or sqlstate '23505' then
    why := app.signin_refusal(sqlstate, sqlerrm);
    if why is null then raise; end if;
    return query select why, null::uuid, null::boolean, null::smallint, null::boolean, null::smallint; return;
  end;
  update app.browser_keys x set failed = 0, used_at = now() where x.id = b.id;
  return query select 'ok'::text, s.member_id, s.is_new, s.trust_level, s.is_admin, null::smallint;
end $$;

-- ---- The account page, as the signed-in member ----

-- How the member signs in: whether they have a PIN, their key file and their browsers (no key material).
create function app.signin_methods() returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member();
begin
  if me is null then return null; end if;
  return jsonb_build_object(
    'pin', (select jsonb_build_object('set_at', x.set_at) from app.signin_pins x where x.member_id = me),
    'key_file', (select jsonb_build_object('created_at', f.created_at, 'used_at', f.used_at) from app.file_keys f where f.member_id = me),
    'browsers', coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'label', b.label, 'created_at', b.created_at, 'used_at', b.used_at)
                            order by b.created_at) from app.browser_keys b where b.member_id = me), '[]'::jsonb));
end $$;

-- The member removes one of their browsers. True if it was theirs and is gone.
create function app.browser_key_remove(p_key_id uuid) returns boolean
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); lbl text;
begin
  if me is null or p_key_id is null then return false; end if;
  delete from app.browser_keys b where b.id = p_key_id and b.member_id = me returning b.label into lbl;
  if lbl is null then return false; end if;
  perform app.notify(me, 'signin_browser', 'A browser was removed',
    'A browser (' || lbl || ') was removed from your account and no longer signs in with your PIN.', '/account', 'member', me,
    'signin:browser:removed:' || p_key_id::text);
  return true;
end $$;

-- The member changes their PIN from a signed-in session, with the current one. Wrong current PINs are counted: the
-- 5th tells Aaron and the member; the 10th ends this session (the member signs in again; nothing is locked).
create function app.pin_change(p_current text, p_new text) returns jsonb
language plpgsql security definer set search_path = pg_catalog as $$
declare me uuid := app.current_member(); x app.signin_pins%rowtype;
begin
  if me is null then return jsonb_build_object('status', 'signed_out'); end if;
  select * into x from app.signin_pins p where p.member_id = me for update;
  if not found then return jsonb_build_object('status', 'no_pin'); end if;
  if p_new is null or p_new !~ '^[0-9]{6}$' or app.pin_weak(p_new) then return jsonb_build_object('status', 'weak_pin'); end if;
  if not app.pin_matches(me, p_current) then
    update app.signin_pins p set change_failed = least(p.change_failed + 1, 10) where p.id = x.id returning * into x;
    if x.change_failed = 5 then
      perform app.pin_wrong(me, 'change', x.id, 5);
    end if;
    if x.change_failed >= 10 then
      update app.signin_pins p set change_failed = 0 where p.id = x.id;
      delete from app.sessions s where s.member_id = me and s.token_hash = current_setting('app.session', true);
      begin
        perform app.notify(null, 'alert', 'A session was signed out after wrong PINs',
          '10 wrong current PINs were typed to change one member''s PIN, so that session was signed out.', '/controls', 'member', me,
          'watch:pinchange:' || x.id::text || ':' || to_char(now() at time zone 'UTC', 'YYYYMMDDHH24MI'));
      exception when others then null;
      end;
      return jsonb_build_object('status', 'signed_out');
    end if;
    return jsonb_build_object('status', 'wrong_pin', 'tries_left', 10 - x.change_failed);
  end if;
  perform app.pin_store(me, p_new);
  perform app.notify(me, 'signin_pin', 'Your PIN was changed', 'Your PIN was changed from your account page. If that '
    || 'wasn''t you, sign out everywhere and sign in again with a code posted through GitHub, which sets a new PIN.', '/account',
    'member', me, 'signin:pinchange:' || x.id::text || ':' || to_char(now(), 'YYYYMMDDHH24MISSUS'));
  return jsonb_build_object('status', 'ok');
end $$;

-- ---- Who may call what, set before handing them over, while dog_owner can still grant ----
revoke execute on function app.pin_digest(uuid, bytea, text), app.pin_store(uuid, text), app.pin_matches(uuid, text),
  app.signin_proof(bytea, text, text, bytea), app.browser_key_add(uuid, bytea, text), app.pin_wrong(uuid, text, uuid, integer),
  app.signin_challenge(text), app.code_status(text), app.browser_key_public(uuid),
  app.code_sign_in_pin(text, text, text, integer, text, text, bytea, text, text, text, bytea, boolean),
  app.file_sign_in_pin(text, text, text, text, integer, text, text, bytea, text, text, text, bytea, text),
  app.browser_sign_in(uuid, text, text, integer, text, text, text, text, bytea),
  app.signin_methods(), app.browser_key_remove(uuid), app.pin_change(text, text) from public;
grant execute on function app.signin_challenge(text), app.code_status(text), app.browser_key_public(uuid),
  app.code_sign_in_pin(text, text, text, integer, text, text, bytea, text, text, text, bytea, boolean),
  app.file_sign_in_pin(text, text, text, text, integer, text, text, bytea, text, text, text, bytea, text),
  app.browser_sign_in(uuid, text, text, integer, text, text, text, text, bytea),
  app.signin_methods(), app.browser_key_remove(uuid), app.pin_change(text, text) to dog_app;

grant create on schema app to dog_signin;
alter function app.pin_digest(uuid, bytea, text) owner to dog_signin;
alter function app.pin_store(uuid, text) owner to dog_signin;
alter function app.pin_matches(uuid, text) owner to dog_signin;
alter function app.signin_proof(bytea, text, text, bytea) owner to dog_signin;
alter function app.browser_key_add(uuid, bytea, text) owner to dog_signin;
alter function app.pin_wrong(uuid, text, uuid, integer) owner to dog_signin;
alter function app.signin_challenge(text) owner to dog_signin;
alter function app.code_status(text) owner to dog_signin;
alter function app.browser_key_public(uuid) owner to dog_signin;
alter function app.code_sign_in_pin(text, text, text, integer, text, text, bytea, text, text, text, bytea, boolean) owner to dog_signin;
alter function app.file_sign_in_pin(text, text, text, text, integer, text, text, bytea, text, text, text, bytea, text) owner to dog_signin;
alter function app.browser_sign_in(uuid, text, text, integer, text, text, text, text, bytea) owner to dog_signin;
alter function app.signin_methods() owner to dog_signin;
alter function app.browser_key_remove(uuid) owner to dog_signin;
alter function app.pin_change(text, text) owner to dog_signin;

-- "Sign out everywhere" (023's app.file_key_revoke) now cancels every browser key too, so a browser someone else added
-- stops working with the key file. It stays the sign-in role's, so it is replaced as that role.
set local role dog_signin;
-- No way in without the check: the site's role no longer calls the two sign-ins that take no PIN (revoked by their
-- owner, which holds the grant since 023 handed them over). The new lanes call them as their owner.
revoke execute on function app.code_sign_in(text, text, text, integer, text), app.file_sign_in(text, text, text, text, integer, text) from dog_app;
-- The independent review of 037 (H1): 025's app.sign_in, which the switched-off GitHub, X and email sign-ins use, made a
-- session straight from a fingerprint the site names, with no PIN and no browser key. The site's role no longer calls it
-- either; switching any of those sign-ins on needs the browser key and PIN step first (db/README.md).
revoke execute on function app.sign_in(text, text[], smallint, smallint, text, text, integer, timestamptz, uuid, text) from dog_app;
create or replace function app.file_key_revoke()
returns integer
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n integer;
begin
  if app.current_member() is null then
    return 0;
  end if;
  delete from app.file_keys f where f.member_id = app.current_member();
  get diagnostics n = row_count;
  delete from app.browser_keys b where b.member_id = app.current_member();
  return n;
end
$$;
set local role dog_owner;
revoke create on schema app from dog_signin;
