-- 033 Second Look v0 (Aaron, Oct 30: "lets build second look"). A record of what Second Look would suggest for each
--   post JEVs held for Aaron: whether the hold was ever its to clear, its score, its suggestion ("clear" or "leave")
--   and its reasons, next to Aaron's own decision (in app.review_flags). In v0 it only records, blind: the record is
--   not shown in Aaron's queue while Second Look is tested, so his decisions stay independent of it and are a fair
--   test. Nothing here can release, hide or change a post, and Aaron still decides every held post. The record is
--   what will show, on real held posts, whether it may one day clear on its own (at most 1 wrong clear in 80; a
--   separate PR, after /privacy and /terms say so).
--   Written only through app.sl_record (dog_jevs, which already reads JEVs's decisions and flags), and only for a post
--   with an open JEVs hold that has no record yet from that model version. The database works out eligibility itself
--   from JEVs's own record of the hold and refuses a record that disagrees. Read only by an administrator (no page
--   shows it yet). Kept as long as the post's row: removing a post only changes its status, so the record stays until
--   the post row is deleted (account deletion deletes it, on delete cascade). No text is copied here, only the score
--   and plain reasons.
set local role dog_owner;

create table app.sl_reviews (
  id uuid primary key default app.uuid_v7(),
  post_id uuid not null references app.posts (id) on delete cascade,
  model text not null check (char_length(model) <= 5 and model ~ '^v[0-9]{1,4}$'),
  eligible boolean not null,
  score real not null check (score between 0 and 1),
  suggestion text not null check (suggestion = any (array['clear', 'leave'])),
  reasons text not null check (char_length(reasons) between 1 and 1000), -- plain reasons, joined by "; " 
  created_at timestamptz not null default now(),
  unique (post_id, model),
  check (eligible or suggestion = 'leave')  -- the never-clear floor, in the database too
);
alter table app.sl_reviews enable row level security;
alter table app.sl_reviews force row level security;
-- An administrator may read them (no page does yet); nobody else, and nobody changes or deletes one (deletion is the
-- post row's cascade).
create policy sl_reviews_select on app.sl_reviews for select to dog_app using (app.actor_kind() = 'admin');
grant select on app.sl_reviews to dog_app;
create policy sl_reviews_jevs_select on app.sl_reviews for select to dog_jevs using (true);
create policy sl_reviews_jevs_insert on app.sl_reviews for insert to dog_jevs with check (true);
grant select (post_id, model), insert (post_id, model, eligible, score, suggestion, reasons) on app.sl_reviews to dog_jevs;

grant create on schema app to dog_jevs;
set local role dog_jevs;

-- Records Second Look's suggestion for a post JEVs is holding for Aaron. Returns true if recorded, false if there is
-- nothing to record (no open JEVs hold on the post, or this model already recorded it). Called by the site in the
-- same transaction as the hold. Anyone with the site's role could call it for any post with an open JEVs hold, so it
-- trusts nothing it is told about eligibility: it works out the never-clear floor itself, from JEVs's latest hold
-- decision on the post, and refuses a record that disagrees (the site's code has a bug if it does).
-- The floor: eligible only if JEVs's scoring didn't fail, no question outside account age (J01), sign-in strength (J02),
-- activity rate (J04), links (J07) and region (J13) scored the post above 0, and one of those five scored 25 or more.
create function app.sl_record(p_post uuid, p_model text, p_eligible boolean, p_score real, p_suggestion text, p_reasons text)
returns boolean
language plpgsql security definer set search_path = pg_catalog
as $$
declare
  v_scores jsonb;
  v_error boolean;
  v_eligible boolean;
begin
  if p_post is null or p_model is null or p_eligible is null or p_score is null or p_suggestion is null or p_reasons is null then
    raise exception 'bad Second Look record' using errcode = '22023';
  end if;
  if not exists (select 1 from app.review_flags f where f.post_id = p_post and f.source = 'classifier' and f.classifier = 'jevs'
                 and f.resolved_at is null) then
    return false;
  end if;
  if exists (select 1 from app.sl_reviews r where r.post_id = p_post and r.model = p_model) then
    return false;
  end if;
  select d.scores, d.error into v_scores, v_error from app.jevs_decisions d
   where d.subject_kind = 'post' and d.subject_id = p_post and d.effect = 'hold' and d.applied
   order by d.created_at desc, d.id desc limit 1;
  if v_scores is null then
    return false;
  end if;
  v_eligible := not v_error
    and not exists (select 1 from jsonb_each(v_scores) e
                    where e.key <> all (array['J01', 'J02', 'J04', 'J07', 'J13'])
                      and (jsonb_typeof(e.value) <> 'number' or (e.value::text)::numeric > 0))
    and exists (select 1 from jsonb_each(v_scores) e
                where e.key = any (array['J01', 'J02', 'J04', 'J07', 'J13'])
                  and jsonb_typeof(e.value) = 'number' and (e.value::text)::numeric >= 25);
  if v_eligible is distinct from p_eligible then
    raise exception 'Second Look and the database disagree on eligibility' using errcode = '22023';
  end if;
  insert into app.sl_reviews (post_id, model, eligible, score, suggestion, reasons)
    values (p_post, p_model, v_eligible, p_score, p_suggestion, p_reasons);
  return true;
end
$$;
revoke execute on function app.sl_record(uuid, text, boolean, real, text, text) from public;
grant execute on function app.sl_record(uuid, text, boolean, real, text, text) to dog_app;

set local role dog_owner;
revoke create on schema app from dog_jevs;
