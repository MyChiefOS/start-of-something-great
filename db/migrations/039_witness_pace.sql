-- 039 The witness counts as stopped after 12 hours without a run, not 2 (Nov 6, after #105 went live).
--   The witness is a GitHub Actions job scheduled every 15 minutes. GitHub runs schedules as best effort: this
--   repository's 15-minute uptime monitor ran 3 to 5 times a day from Oct 30 to Nov 6, 5 to 8 hours apart, and the
--   witness's own schedule hadn't started 1.5 hours after it was added. With a 2-hour rule the site called the witness
--   stopped most of every day and alerted Aaron daily for GitHub's pace, not for a fault. At 12 hours the alert means
--   it has really stopped. Only the threshold changes: app.log_witness_report is 038's, word for word, otherwise.
--   Its owner (dog_log), its rights (security definer) and who may call it (dog_app) stay as 038 set them.
set local role dog_owner;
grant create on schema app to dog_log;
set local role dog_log;
create or replace function app.log_witness_report(p_size bigint, p_root bytea, p_witnessed_at timestamptz, p_alarm text) returns text
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  n bigint;
  w record;
  why text;
begin
  select x.size into n from app.log_head x where x.singleton;
  select * into w from app.log_witness x where x.singleton for update;
  -- An alarm or a mismatch stays until a reviewed migration clears it (app.log_clear_alarm): nothing the site's login
  -- reports clears it, so a copy of the right root sent by the site itself can't mark the log verified (M3).
  if w.alarm then
    update app.log_witness x set witnessed_at = coalesce(p_witnessed_at, x.witnessed_at), checked_at = now() where x.singleton;
    return 'unverified';
  end if;
  if p_alarm is not null and p_alarm <> '' then
    why := 'The witness on GitHub raised an alarm: ' || left(regexp_replace(p_alarm, '[^ -~]', '', 'g'), 200);
  elsif p_size is null or p_root is null then
    update app.log_witness x set status = case when x.status = 'unverified' then x.status else 'unknown' end, checked_at = now() where x.singleton;
    return (select x.status from app.log_witness x where x.singleton);
  elsif octet_length(p_root) <> 32 or p_size < 1 then
    why := 'The witness''s copy on GitHub isn''t a checkpoint of this log.';
  elsif p_size > n then
    why := 'The witness on GitHub has a checkpoint of ' || p_size || ' entries, but the log has only ' || n || '.';
  elsif app.log_root(p_size) <> p_root then
    why := 'The witness''s copy of checkpoint ' || p_size || ' on GitHub doesn''t match this log''s tree.';
  end if;
  if why is not null then
    update app.log_witness x set witness_size = case when octet_length(p_root) = 32 then p_size else x.witness_size end,
      witnessed_at = p_witnessed_at, alarm = true where x.singleton;
    perform app.log_unverified(why);
    return 'unverified';
  end if;
  -- Once unverified, the log stays so until the reason is gone: a witness copy that matches again, and the tree
  -- reaching its own checkpoints. A witness that hasn't run for 12 hours is "stale": an alert, once a day (039).
  update app.log_witness x set status = case when not x.self_ok then 'unverified'
                                             when p_witnessed_at < now() - interval '12 hours' then 'stale' else 'ok' end,
    reason = case when not x.self_ok then x.reason when p_witnessed_at < now() - interval '12 hours'
                  then 'The witness on GitHub last ran ' || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC.' else '' end,
    witness_size = p_size, witness_root = p_root, witnessed_at = p_witnessed_at, checked_at = now()
  where x.singleton;
  if p_witnessed_at < now() - interval '12 hours' then
    perform app.notify(null, 'alert', 'The public log''s witness has stopped', 'The witness job on GitHub last ran '
      || to_char(p_witnessed_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC, so new receipts show as not yet witnessed. The site keeps running.',
      '/security#log', null, null, 'log.stale.' || to_char(now() at time zone 'UTC', 'YYYY-MM-DD'));
  end if;
  return (select x.status from app.log_witness x where x.singleton);
end
$$;

set local role dog_owner;
revoke create on schema app from dog_log;
