-- 087 The gaps the Nov 26 simulation found (Aaron, Nov 26: "open a PR to fix the gaps identified"; "think of
--   permations of that attack so the system can catch other attacks developed in novel ways that exhibit similar
--   pattens"). Each rule reads the input after its disguises are undone, and matches the attack's shape:
--     W43   block  a reverse or bind shell in code (/dev/tcp, nc -e, socat exec:, sh -i >&, mkfifo, socket + pty, ...)
--     W43b  flag   the same inside a test or fixture file
--     W44   block  code execution hidden or decoded: a dangerous name that appears only once strings are joined or
--                  escapes, char codes, base64, hex or reversals are undone; eval/exec of decoded data; a sink read
--                  by computed name (['ex'+'ec']); JSFuck-style bracket code
--     W44b  flag   the same inside a test or fixture file
--     W45   block  clear spam (a spam topic with an offer and a money promise or off-platform contact, ...), read with
--                  digits and symbols as letters, spaced letters joined, repeats squeezed
--     W45b  flag   looks like spam (fewer signs), and W45 inside a test or fixture file
--     W13b  flag   a request to build or run an attack (writing an exploit, ransomware, a reverse shell; attacking a
--                  site): flagged, not blocked, since security work asks about these honestly
--   The firewall (wall/firewall.js), the file scanner (EICAR) and the YARA fix are in code; their rules are W35-W42.

reset role;
alter table app.wall_rules disable row level security;
insert into app.wall_rules (rule, effect, what) values
  ('W43', 'block', 'A reverse or bind shell in code (a shell wired to a network connection, in any of its usual forms)'),
  ('W43b', 'flag', 'A reverse or bind shell inside a test or fixture file'),
  ('W44', 'block', 'Code execution hidden or decoded (a dangerous call that shows only once the code''s disguises are undone)'),
  ('W44b', 'flag', 'Hidden or decoded code execution inside a test or fixture file'),
  ('W45', 'block', 'Clear spam (a spam topic with an offer and a money promise or off-platform contact), however it is spelled'),
  ('W45b', 'flag', 'Looks like spam (fewer signs than W45)'),
  ('W13b', 'flag', 'A request to build or run an attack (an exploit, malware, a reverse shell, attacking a site): flagged for the reviewers');
update app.wall_rules set what = 'A malware signature that matched files in 3 or more pull requests or 10 or more files in one run, or a signature check that could not run' where rule = 'W42b';
update app.wall_rules set what = 'A web attack in a request''s path, query, headers or body, in any encoding: SQL injection, cross-site scripting, path traversal, command injection, file inclusion, Log4Shell lookups, template injection' where rule = 'W35';
update app.wall_rules set what = 'A known attack scanner, or a probe for a file this site never serves (a request with no user agent is only flagged)' where rule = 'W37';
update app.wall_rules set what = 'Too many requests a minute from one address or one network (answered 429, try again in a minute; never a lockout); a flood across many networks is flagged' where rule = 'W36';
update app.wall_rules set what = 'A request from an address or range on the security wiki''s blocking threat lists (Spamhaus DROP, Feodo Tracker), IPv4 or IPv6' where rule = 'W38';
alter table app.wall_rules enable row level security;
set local role dog_owner;

-- 087: code with its disguises undone, for the code rules (W43, W44). Returns the lower-cased code, then on new
-- lines what each disguise hid: string pieces joined ('child_' + 'process'), escapes decoded (\x63\x68), char codes
-- decoded (String.fromCharCode(99,104), chr(99)+chr(104)), base64 and hex literals decoded, and reversed strings
-- read forwards. Bounded: at most 2,000 replacements and 40 decoded literals. A character Postgres can't hold (0, a
-- lone surrogate) reads as a space, and if anything else goes wrong the code is returned as written: this function never
-- raises, so it can never stop the Wall from checking a submission.
create function app.wall_safe_chr(p bigint) returns text
language sql immutable set search_path = pg_catalog as $f$
  select case when p is null or p <= 0 or p > 1114111 or p between 55296 and 57343 then ' ' else lower(chr(p::int)) end
$f$;
revoke execute on function app.wall_safe_chr(bigint) from public;

create function app.wall_deobfuscate(p_text text) returns text
language plpgsql immutable set search_path = pg_catalog as $$
declare
  n text := lower(translate(left(coalesce(p_text, ''), 400000), 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  d text;
  extra text := '';
  m text[];
  x text;
  k int := 0;
  codes text;
begin
  d := n;
  for i in 1 .. 3 loop
    d := regexp_replace(d, '([''"`])[[:space:]]*(\+|\.\.|\|\||&)[[:space:]]*([''"`])', '', 'g');                -- 'a' + 'b', 'a' .. 'b', 'a' || 'b'
  end loop;
  d := regexp_replace(d, '\$\{[[:space:]]*[''"`]([^''"`]*)[''"`][[:space:]]*\}', '\1', 'g');                    -- `${'a'}`
  d := regexp_replace(d, '\[[[:space:]]*([''"`][^''"`\]]*[''"`][[:space:]]*,[[:space:]]*)+[''"`][^''"`\]]*[''"`][[:space:]]*\]\.join\([''"`]{2}\)',
         '<<join>>', 'g');
  for m in select regexp_matches(n, '\[(([[:space:]]*[''"`][^''"`\]]{0,40}[''"`][[:space:]]*,?)+)\]\.join\([''"`]{2}\)', 'g') loop    -- ['ch','ild'].join('')
    exit when k > 40; k := k + 1;
    extra := extra || E'\n' || regexp_replace(m[1], '[''"`,[:space:]]', '', 'g');
  end loop;
  -- \xHH and \uHHHH escapes.
  for i in 1 .. 2000 loop
    m := regexp_match(d, '\\x([0-9a-f]{2})|\\u([0-9a-f]{4})|\\u\{([0-9a-f]{1,6})\}');
    exit when m is null;
    d := regexp_replace(d, '\\x' || coalesce(m[1], '') || '|\\u' || coalesce(m[2], '') || '|\\u\{' || coalesce(m[3], '') || '\}',
           app.wall_safe_chr(('x' || lpad(coalesce(m[1], m[2], m[3]), 8, '0'))::bit(32)::int));
    exit when position('\x' in d) = 0 and position('\u' in d) = 0;
  end loop;
  -- Char codes: String.fromCharCode(99, 104, ...), chr(99) + chr(104), [char]99+[char]104.
  for m in select regexp_matches(n, 'fromcharcode\(([0-9[:space:],]{3,250})\)', 'g') loop
    exit when k > 80; k := k + 1;
    select string_agg(app.wall_safe_chr(v::bigint), '') into codes from unnest(string_to_array(regexp_replace(m[1], '[[:space:]]', '', 'g'), ',')) v where v ~ '^[0-9]{1,7}$';
    extra := extra || E'\n' || coalesce(codes, '');
  end loop;
  for m in select regexp_matches(n, '((chr|char|\[char\])[[:space:]]*\(?[[:space:]]*[0-9]{1,6}[[:space:]]*\)?[[:space:]]*[+.,&]?[[:space:]]*){3,}', 'g') loop
    exit when k > 80; k := k + 1;
    select string_agg(app.wall_safe_chr(v[1]::bigint), '') into codes from regexp_matches(m[1], '([0-9]{1,6})', 'g') v;
    extra := extra || E'\n' || coalesce(codes, '');
  end loop;
  -- Base64 and hex literals, decoded when they decode to text.
  -- Base64 is read from the code as written (case matters), with string pieces joined.
  for x in select (regexp_matches(regexp_replace(left(coalesce(p_text, ''), 400000), '([''"`])[[:space:]]*\+[[:space:]]*([''"`])', '', 'g'),
                                  '[''"`]([A-Za-z0-9+/_-]{6,}={0,2})[''"`]', 'g'))[1] limit 40 loop
    begin
      codes := convert_from(decode(rpad(translate(x, '-_', '+/'), ((char_length(x) + 3) / 4) * 4, '='), 'base64'), 'UTF8');
      if codes !~ '[^[:print:][:space:]]' then extra := extra || E'\n' || lower(codes); end if;
    exception when others then null;
    end;
  end loop;
  for x in select (regexp_matches(d, '(?:0x|[''"`])([0-9a-f]{6,})[''"`]?', 'g'))[1] limit 40 loop
    begin
      codes := convert_from(decode(x, 'hex'), 'UTF8');
      if codes !~ '[^[:print:][:space:]]' then extra := extra || E'\n' || lower(codes); end if;
    exception when others then null;
    end;
  end loop;
  -- Reversed strings, only the literal actually reversed: 'ssecorp_dlihc'.split('').reverse().join(''), 'x'[::-1],
  -- strrev('x'), [...'x'].reverse().
  for x in select (regexp_matches(n, '[''"`]([^''"`\n]{2,80})[''"`][[:space:]]*(\.split\([''"`]{2}\)[[:space:]]*\.reverse\(|\[::-1\])', 'g'))[1] limit 40 loop
    extra := extra || E'\n' || reverse(x);
  end loop;
  for x in select (regexp_matches(n, '(strrev\(|\[\.\.\.)[[:space:]]*[''"`]([^''"`\n]{2,80})[''"`]', 'g'))[2] limit 40 loop
    extra := extra || E'\n' || reverse(x);
  end loop;
  return d || extra;
exception when others then
  return n;
end $$;
revoke execute on function app.wall_deobfuscate(text) from public;

-- 087: how spam-like one paragraph is: 2 clear spam (W45), 1 looks like spam (W45b), 0 not. Signals must occur in the
-- same paragraph, so a long document that mentions a scam in one place and crypto in another isn't spam.
create function app.wall_spam_level(p_para text) returns int
language plpgsql immutable set search_path = pg_catalog as $f$
declare
  t text := left(coalesce(p_para, ''), 4000);
  n text;
  l text;
  topic boolean; offer boolean; money boolean; push boolean; contact boolean; shout boolean;
  g text;
  g2 text;
begin
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  n := regexp_replace(regexp_replace(n, '[​‌⁠-⁤﻿]', '', 'g'), '[[:space:]]+', ' ', 'g');
  -- Digits and symbols read as the letters they stand for (fr33 b1tc0in), letters spelled apart joined (f r e e,
  -- f.r.e.e), repeated letters squeezed (freeee).
  l := translate(n, '0134578@$!|€', 'oieastbasile');
  l := regexp_replace(l, '([a-z])[._*~-]+(?=[a-z])', '\1', 'g');
  -- Text spelled with spaces between letters (f r e e  b i t c o i n) runs words together once joined, so it is also
  -- read with every space removed, for the long, unambiguous words only.
  g := case when l ~ '(\m[a-z][[:space:]]+){4,}' then regexp_replace(l, '[^a-z0-9$%./]', '', 'g') else '' end;
  -- The same with digits kept, for amounts (s e n d 0 . 1).
  g2 := case when g <> '' then regexp_replace(n, '[^a-z0-9$%./]', '', 'g') else '' end;
  l := regexp_replace(l, '\m([a-z]) (?=[a-z]\M)', '\1', 'g');
  l := regexp_replace(l, '([a-z])\1{2,}', '\1\1', 'g');
  topic := l ~ '\m(bitcoin|btc|eth|ethereum|usdt|tether|crypto|cryptocurrency|solana|xrp|doge|dogecoin|bnb|nfts?|metamask|binance|coinbase|seed ?phrase|forex|binary options|casino|betting|slots?|viagra|cialis|pharmacy|payday loans?|backlinks|seo services|followers|escorts?)\M';
  offer := l ~ '\m(free|giveaway|give away|airdrop|bonus|prize|winners?|you (have )?won|reward|gift|double (your|it)|2x|10x|100x|cashback|jackpot)\M';
  -- Amounts keep their digits: the money promise is read on the text before digits became letters too.
  money := n ~ '((send|deposit|transfer|pay|invest) [$€£]?[0-9.,]+( ?[a-z$]{1,10})?[^.!?\n]{0,40}\m(get|receive|back|return|double)|guaranteed? (profit|returns?|income)|[0-9]+ ?% (daily|weekly|monthly|per day|profit|returns?|roi)|make [$€£]?[0-9,]+ (a|per) (day|week|hour)|passive income|financial freedom|investment (opportunity|plan))' or l ~ '((send|deposit|transfer|pay|invest) [$€£]?[0-9.,]+( ?[a-z$]{1,10})?[^.!?\n]{0,40}\m(get|receive|back|return|double)|guaranteed? (profit|returns?|income)|[0-9]+ ?% (daily|weekly|monthly|per day|profit|returns?|roi)|make [$€£]?[0-9,]+ (a|per) (day|week|hour)|passive income|financial freedom|investment (opportunity|plan))';
  -- An amount written in look-alike letters (o.i for 0.1) still counts as an amount.
  money := money or l ~ '\m(send|deposit|transfer|pay|invest) [$€£]?[0-9oilsz.,]{1,8}( ?[a-z$]{1,10})?[^.!?\n]{0,40}\m(get|receive|back|return|double)\M';
  push := l ~ '(\m(send|dm|join|register|sign ?up|click|visit|buy|claim|act|hurry|order)\M[^.!?\n]{0,25}\m(now|today|here|fast|asap|immediately)\M|limited (time|offer|spots)|only today|last chance|don.?t miss|before it.?s gone)';
  contact := l ~ '(telegram|whatsapp|t\.me/|wa\.me/|\mdm me\M|message me|contact me (on|via|at)|wechat|\mkik\M)';
  if g <> '' then
    topic := topic or g ~ '(bitcoin|ethereum|crypto|usdt|tether|dogecoin|binance|coinbase|metamask|casino|forex|viagra|cialis|payday)';
    offer := offer or g ~ '(giveaway|airdrop|jackpot|doubleyour|youwon|youhavewon|freebitcoin|freecrypto|cashback|bonus|prize)';
    money := money or g2 ~ '(send[0-9.]+[a-z]{0,10}(and)?(get|receive)|guaranteed(profit|return|income)|[0-9]+%(daily|weekly|monthly|profit|return))';
    push := push or g ~ '(sendnow|claimnow|clicknow|joinnow|actnow|buynow|limitedtime|lastchance|onlytoday)';
    contact := contact or g ~ '(telegram|whatsapp|t\.me/|wa\.me/|dmme|messageme|contactmeon|wechat)';
  end if;
  shout := t ~ '!{3,}' or (char_length(t) > 20 and char_length(regexp_replace(t, '[^A-Z]', '', 'g')) * 2 > char_length(regexp_replace(t, '[^A-Za-z]', '', 'g')));
  if topic and ((offer and (money or contact)) or (money and (push or contact or shout)) or (offer and push and shout)) then
    return 2;
  elsif topic and ((offer and (push or shout)) or money or (contact and push)) then
    return 1;
  end if;
  return 0;
exception when others then
  return 0;
end $f$;
revoke execute on function app.wall_spam_level(text) from public;

create or replace function app.wall_text_flags(p_text text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  t text := coalesce(p_text, '');
  n text;
  l text;
  f jsonb := '[]'::jsonb;
  lvl int;
begin
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  n := replace(replace(replace(replace(n, '&#8203;', ''), '&#x200b;', ''), '&amp;', '&'), '&nbsp;', ' ');
  n := regexp_replace(regexp_replace(n, '[​‌⁠-⁤﻿]', '', 'g'), '[[:space:]]+', ' ', 'g');
  if t ~ '[​‌⁠-⁤﻿]' or t ~ '[\U000E0000-\U000E007F]' or p_text ~ '&#(8203|x200b|8204|x200c|65279|xfeff);' then
    f := f || '["W07a hidden characters"]';
  end if;
  if n ~ '(ignore (all )?(the )?(previous|prior|above)( instructions)?|disregard (the |all )?(task|rules|instructions)|(reveal|print|ignore) (the |your )?system prompt|answer pass|mark (both|all|it|them|this) (as )?pass|checks are already satisfied|you are now (in )?[a-z]+ mode)' then
    f := f || '["W07b instruction aimed at a checker or agent"]';
  end if;
  if n ~ '\m(bit\.ly|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|rb\.gy|cutt\.ly)/' then
    f := f || '["W06 link shortener"]';
  end if;
  if n ~ 'https?://[^[:space:]"'']+[?&](u|url|redirect|next|target|dest|to)=' then
    f := f || '["W23 redirecting link"]';
  end if;
  if app.wall_metadata_address(n) then
    f := f || '["W22 cloud-metadata address"]';
  elsif n ~ '(://localhost|://127\.0\.0\.1|://10\.[0-9]+\.[0-9]+\.[0-9]+|://192\.168\.)' then
    f := f || '["W22b local or private address"]';
  end if;
  if t ~ '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)' and t !~ 'AKIA[0-9A-Z]*EXAMPLE' then
    f := f || '["W11 credential in content"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  -- 087 (Aaron, Nov 26: catch the permutations): spam and attack requests are read on a copy with digits and symbols
  -- read as the letters they stand for (fr33 b1tc0in), letters spelled apart joined (f r e e, f.r.e.e), and
  -- repeated letters squeezed (freeee).
  l := translate(n, '0134578@$!|€', 'oieastbasile');
  l := regexp_replace(l, '([a-z])[._*~-]+(?=[a-z])', '\1', 'g');
  -- Spam, a paragraph at a time (at most 200 paragraphs).
  lvl := coalesce((select max(app.wall_spam_level(x)) from (select x from regexp_split_to_table(left(t, 400000), '
[[:space:]]*
') x limit 200) y), 0);
  if lvl = 2 then
    f := f || '["W45 spam"]';
  elsif lvl = 1 then
    f := f || '["W45b looks like spam"]';
  end if;
  if l ~ '\m(write|build|create|make|develop|code|give me|generate|craft|produce|run|deploy|launch|execute|send|spread|plant|install)\M[^.?!\n]{0,60}\m(exploits?|payloads?|ransomware|malware|virus(es)?|worms?|trojans?|keyloggers?|botnets?|backdoors?|rootkits?|(info)?stealers?|rats?|reverse shells?|web ?shells?|ddos|dos attacks?|phishing (pages?|kits?|sites?|emails?)|credential harvesters?|cryptominers?|zero[- ]?days?)\M'
     or l ~ '\m(exploit|attack|hack|breach|compromise|pwn|ddos|deface|take down|brute ?force)\M[^.?!\n]{0,30}\m(this|that|the|their|his|her|our|my|a|an|your)?[[:space:]]*(server|site|website|network|account|database|system|host|router|company|target|domain|app)s?\M'
     or l ~ 'exploits? (for|against|targeting|of) cve-[0-9]' then
    f := f || '["W13b request to build or run an attack"]';
  end if;
  if n ~ '\m(create|spawn|register|make) [0-9]+ (helper )?(agents|accounts|keys|bots)\M' then
    f := f || '["W20 asks to spawn agents or accounts"]';
  end if;
  return f;
end $$;

create or replace function app.wall_code_flags(p_path text, p_added text, p_task text) returns jsonb
language plpgsql immutable set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  t text := coalesce(p_added, '');
  n text;
  task text := lower(coalesce(p_task, ''));
  joined text;
  d text;
  c text;
  nc text;
begin
  if p_path ~* '\.(md|mdx|txt|rst)$' then return f; end if;  -- prose is read by the text rules
  n := lower(translate(t, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  if n ~ '(crontab|systemd|\.service\M|(curl|wget|fetch)[^\n|]*\|[[:space:]]*(sudo[[:space:]]+(-[a-z]+[[:space:]]+)*)?(/usr)?(/bin/)?(env[[:space:]]+)?(ba|z|da|k|fi)?sh\M|git remote add|deploy[_-]?key)' then
    f := f || '["W05 persistence in code"]';
  end if;
  -- The whole environment, not one variable: process.env.X, process.env[name] and os.environ.get(...) are fine.
  if t ~ '(Object\.(keys|entries|values|assign)\([^)]*process[[:space:]]*(\.[[:space:]]*env|\[[[:space:]]*[''"`]env)|JSON\.stringify\([[:space:]]*process[[:space:]]*\.[[:space:]]*env[[:space:]]*[),]|\.\.\.[[:space:]]*process[[:space:]]*\.[[:space:]]*env|process[[:space:]]*\[[[:space:]]*[''"`]env[''"`][[:space:]]*\]|\{[^}]*\menv\M[^}]*\}[[:space:]]*=[[:space:]]*process\M|[=(,][[:space:]]*process[[:space:]]*\.[[:space:]]*env[[:space:]]*($|[;,)\n])|os\.environ[[:space:]]*($|[),;\n]|\.(copy|items|keys|values)\()|dict\([[:space:]]*os\.environ|for [a-z_, ]+ in os\.environ)' then
    f := f || '["W21 whole environment used as data"]';
  end if;
  if t ~ '\m(fetch|axios|https?\.(get|request)|XMLHttpRequest|net\.connect|child_process|execSync|exec\()' or t ~ 'require\([''"]dns[''"]\)'
     then
    if task !~ '\m(api|client|http|upload|retry|request|download|webhook|dns|build|network|fetch)\M' then
      f := f || '["W12 network or exec call the task didn''t ask for"]';
    end if;
  end if;
  if app.wall_metadata_address(n) then
    f := f || '["W22 cloud-metadata address"]';
  elsif n ~ '(\.internal\M|localhost|127\.0\.0\.1|\m10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.)' then
    f := f || '["W22b local or private address"]';
  end if;
  if n ~ '\m(nmap|masscan|sqlmap|metasploit|hydra)\M' or n ~ '/etc/passwd' then
    f := f || '["W13 recon or exploit material"]';
  end if;
  -- 087 (Aaron, Nov 26: catch the permutations): the code with its disguises undone (strings joined, escapes and
  -- char codes decoded, base64 and hex literals decoded and added, reversed strings added). A dangerous name that
  -- appears only once the disguise is undone was hidden on purpose: that is W44, however it was hidden.
  -- Full-line comments are left out (a comment never runs; this repository's own docs describe attacks in them).
  c := regexp_replace(t, '(^|\n)[[:space:]]*(//|#|\*|/\*|--|<!--)[^\n]*', '\1', 'g');
  nc := lower(translate(c, 'оОаАеЕсСрРхХіІѕЅ', 'ooaaeeccppxxiiss'));
  d := app.wall_deobfuscate(c);
  -- The pieces are joined first (|| binds no tighter than ~), then matched.
  if d ~ ('(/dev/(tcp|udp)/[^[:space:]/]+/[0-9]+'
       || '|\m(nc|ncat|netcat|nc\.traditional|nc\.openbsd)\M[^\n;|]{0,120}[[:space:]]-[a-z]*[ec][a-z]*\M'
       || '|\msocat\M[^\n]{0,200}\m(exec|system):'
       || '|\m(ba|z|k|da|c|tc|fi)?sh[[:space:]]+-i\M[^\n]{0,80}(>&|0>&1|<&|>[[:space:]]*/dev/)'
       || '|\mmkfifo\M[^\n]{0,200}\m(nc|ncat|sh|bash|telnet|openssl)\M'
       || '|socket[^\n]{0,250}(pty\.spawn|dup2|subprocess\.(call|popen|run)|os\.system|/bin/(ba)?sh|exec(ve)?\()'
       || '|fsockopen\([^\n]{0,200}(exec|shell_exec|system|proc_open|passthru|popen)'
       || '|(net\.sockets\.tcpclient|system\.net\.sockets)[^\n]{0,250}[^\n]{0,250}(invoke-expression|\miex\M|getstream)'
       || '|\mopenssl s_client\M[^\n]{0,200}\|[[:space:]]*(/bin/)?(ba)?sh'
       || '|\mtelnet\M[^\n]{0,80}\|[^\n]{0,40}\m(ba)?sh\M'
       || '|\m(meterpreter|msfvenom|reverse_tcp|bind_tcp|shell_reverse_tcp|reverse_https)\M'
       || '|(net\.(connect|createconnection)|new net\.socket)\(.{0,250}[^\n]{0,250}\m(spawn|exec|execfile)\([^)]{0,60}\m(sh|bash|cmd|powershell)\M)') then
    f := f || '["W43 reverse or bind shell"]';
  end if;
  -- A name that reaches the system, as a whole word, present once the disguises are undone but not in the code as
  -- written: it was hidden on purpose, whichever way.
  if exists (select 1 from unnest(array['child_process', 'exec', 'execsync', 'execfile', 'spawn', 'spawnsync', 'fork', 'eval', 'function', 'system', 'popen', 'subprocess',
                 '__import__', 'os', 'vm', 'require', 'settimeout', 'setinterval', 'shell_exec', 'passthru', 'proc_open', 'invoke-expression', 'iex', 'downloadstring',
                 'frombase64string', 'runinnewcontext', 'runinthiscontext', 'constructor', 'getruntime', 'processbuilder', 'cmd.exe', 'powershell', '/bin/sh', '/bin/bash']) k
             where d ~ ('(^|[^a-z0-9_])' || replace(replace(k, '.', '\.'), '/', '\/') || '($|[^a-z0-9_])')
               and nc !~ ('(^|[^a-z0-9_])' || replace(replace(k, '.', '\.'), '/', '\/') || '($|[^a-z0-9_])'))
     -- A member read by a computed name that is itself decoded or built from pieces: obj[atob(...)], obj[['e','v'].join('')].
     or nc ~ '[a-z0-9_$)\]]\[[[:space:]]*(window\.|globalthis\.)?(atob|buffer\.from|string\.fromcharcode|unescape|decodeuricomponent|\[[^]]*\]\.join|[''"`][^''"`]*[''"`]\.split|[''"`][^''"`]*[''"`][[:space:]]*\+[[:space:]]*[''"`])'
     or nc ~ '\m(eval|function|exec|execsync|settimeout|setinterval|system|popen|invoke-expression|iex|execute|compile)[[:space:]]*\(?[[:space:]]*\(?[[:space:]]*(window\.)?(atob|buffer\.from|base64|b64decode|decodeuricomponent|unescape|string\.fromcharcode|fromcharcode|bytes\.fromhex|codecs\.decode|zlib\.decompress|frombase64string|gunzip|inflate|rot13|reverse)'
     or d ~ '\[[[:space:]]*[''"`](exec|execsync|spawn|spawnsync|eval|execfile|fork|system|popen|constructor|__proto__)[''"`][[:space:]]*\]'
     or nc ~ '\.split\([''"`]{2}\)\.reverse\(\)\.join\([''"`]{2}\)[^\n]{0,60}\m(eval|exec|function|require)'
     or nc ~ '(\[[[:space:]]*\]|\(\[\]|!\[\]|\+\[\]){3}' then
    f := f || '["W44 hidden or decoded code execution"]';
  end if;
  if t ~ '(\m(it|test|describe|context|suite)[[:space:]]*\.[[:space:]]*(skip|only|todo)[[:space:]]*\(|\m(xit|xtest|xdescribe|xcontext)[[:space:]]*\(|@pytest\.mark\.skip|\{[[:space:]]*skip:[[:space:]]*true|expect\([^)]*\)\.toBe\([A-Za-z0-9_]+\)[[:space:]]*//[[:space:]]*matches current)' then
    f := f || '["W15 weakens or pins a test"]';
  end if;
  if t ~ 'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*return[[:space:]]*\{[[:space:]]*ok:[[:space:]]*true' then
    f := f || '["W16 swallows errors as success"]';
  end if;
  if p_path ~* '(^|/)package\.json$' and t ~ '"(pre|post)?(install|prepare|prepublish)(only)?"[[:space:]]*:' then
    f := f || '["W19 install hook"]';
  end if;
  joined := regexp_replace(regexp_replace(regexp_replace(t, 'data:image/svg\+xml;base64,[A-Za-z0-9+/=]+', '', 'g'),
              'integrity="sha(256|384|512)-[^"]+"', '', 'g'), '["''`][[:space:]]*\+[[:space:]]*["''`]', '', 'g');
  if joined ~ '[A-Za-z0-9+/]{120,}' then
    f := f || '["W09 encoded data"]';
  end if;
  if p_path ~* '\.(png|jpg|gif|bin|exe|so|dll|wasm)$' and task !~ '\m(logo|image|icon|png|wasm|asset|binary)\M' then
    f := f || '["W10 binary the task didn''t ask for"]';
  end if;
  -- Each flag once (the code rules and the text rules can both see an address).
  return coalesce((select jsonb_agg(z.v order by z.o) from (select distinct on (e.v) e.v, e.o
                     from jsonb_array_elements(f || coalesce((select jsonb_agg(x) from jsonb_array_elements(app.wall_text_flags(t)) x
                     -- 087: a request to build an attack, and maybe-spam, are about posts and tasks: not read in code files.
                     where split_part(x #>> '{}', ' ', 1) <> all (array['W13b', 'W45b'])), '[]'::jsonb)) with ordinality e(v, o) order by e.v, e.o) z), '[]'::jsonb);
end $$;
revoke execute on function app.wall_code_flags(text, text, text) from public;

create or replace function app.wall_files_flags(p_task uuid, p_files jsonb) returns jsonb
language plpgsql stable security definer set search_path = pg_catalog as $$
declare
  f jsonb := '[]'::jsonb;
  paths text[];
  deps text[];
  fl jsonb;
  added text;
  m text[];
  adv text;
  fname text;
  task text;
  ext text;
  allow_deps constant text[] := array['lodash', 'dayjs', 'axios', 'zod', 'react', 'express', 'postgres', 'jest', 'typescript'];
begin
  select coalesce(array_agg(s.value) filter (where s.kind = 'path'), '{}'), coalesce(array_agg(s.value) filter (where s.kind = 'dependency'), '{}')
    into paths, deps from app.work_task_scope s where s.task_id = p_task;
  select coalesce(t.title, '') || E'\n' || coalesce(t.description, '') into task from app.work_tasks t where t.id = p_task;
  for fl in select * from jsonb_array_elements(coalesce(p_files, '[]'::jsonb)) loop
    fname := coalesce(fl ->> 'filename', '');
    added := (select string_agg(substr(l, 2), E'\n') from regexp_split_to_table(coalesce(fl ->> 'patch', ''), E'\n') l where l ~ '^\+' and l !~ '^\+\+\+');
    if cardinality(paths) > 0 and not exists (select 1 from unnest(paths) p where fname like p || '%')
       and fname !~ '^(CHANGELOG|README)' and fname !~ '^src/(shared|types)/' and fname !~ 'package-lock\.json$' then
      f := f || jsonb_build_array('W04 file outside the task''s declared paths: ' || left(fname, 120));
    end if;
    -- 081 review: no task wording exempts a protected file. Inside the poster's declared paths it is flagged (goes ahead,
    -- reviewers see it); anywhere else it is blocked.
    if fname ~* '(^|/)(\.github/|CODEOWNERS$|\.semgrep|jevs/|secondlook/|thirdlook/|wall/|scripts/check|\.husky/|Dockerfile[^/]*$|[^/]*\.dockerfile$|vercel\.json$|db/migrations/|\.npmrc$)' then
      -- Flag, not block, only when the task is about it in both ways: a declared path that itself names the protected place
      -- (.github/workflows/ does; src/ doesn't) and task wording about it. Wording alone, or a broad path alone, blocks.
      if cardinality(paths) > 0 and exists (select 1 from unnest(paths) p where lower(fname) like lower(p) || '%'
           and p ~* '(^|/)(\.github/|CODEOWNERS$|\.semgrep|jevs/|secondlook/|thirdlook/|wall/|scripts/check|\.husky/|Dockerfile[^/]*$|[^/]*\.dockerfile$|vercel\.json$|db/migrations/|\.npmrc$)')
         and lower(coalesce(task, '')) ~ '\m(ci|workflow|nightly|action|pipeline|migration|codeowners|owners|docker|deploy|hook)s?\M' then
        f := f || jsonb_build_array('W03b protected file in the declared paths: ' || left(fname, 120));
      else
        f := f || jsonb_build_array('W03 protected file: ' || left(fname, 120));
      end if;
    end if;
    -- 084: the scan of the file's contents, made by the Wall's scanner in the facts workflow (wall/files.js).
    if jsonb_typeof(fl -> 'scan' -> 'flags') = 'array' then
      f := f || (fl -> 'scan' -> 'flags');
    end if;
    if not (fl ? 'patch') and not (fl ? 'scan') and coalesce(fl ->> 'status', '') <> 'removed' then
      f := f || jsonb_build_array('W27 changed file the Wall couldn''t read: ' || left(fname, 120));
    end if;
    if fname ~ '(^|/)package\.json$' then
      for m in select regexp_matches(coalesce(added, ''), '"([@a-z0-9._/-]+)"[[:space:]]*:[[:space:]]*"([\^~]?)([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*|[0-9][^"]*)"', 'g') loop
        if m[1] <> all (array['version', 'node']) and m[1] <> all (case when cardinality(deps) > 0 then deps else allow_deps end) then
          f := f || jsonb_build_array('W18 dependency outside the task''s declared list: ' || left(m[1], 100));
        end if;
        -- 074's check, kept: an added dependency pinned to a version an advisory in the active security wiki names.
        adv := app.wiki_bad_package('npm', m[1], m[3]);
        if adv is not null then
          f := f || jsonb_build_array('W25 known-bad package version (security wiki, ' || adv || '): ' || left(m[1] || '@' || m[3], 120));
        end if;
      end loop;
    end if;
    -- 082 review: inside a test or fixture file, a phrase aimed at a checker is flagged (W07c), not blocked: the
    -- project's red-team tests quote them. Reviewers still see it.
    if fname ~* '(^|/)(test|tests|__tests__|spec|fixtures?|redteam|__fixtures__)/|\.(test|spec)\.[a-z]+$' then
      f := f || coalesce((select jsonb_agg(case when x like 'W07b %' then 'W07c' || substr(x, 5) || ' (in a test or fixture)'
                                                 -- 087: the red-team tests quote shells and hidden code: flagged there.
                                                 when x like 'W43 %' or x like 'W44 %' or x like 'W45 %' then split_part(x, ' ', 1) || 'b' || substr(x, length(split_part(x, ' ', 1)) + 1) || ' (in a test or fixture)'
                                                 else x end)
                            from jsonb_array_elements_text(app.wall_code_flags(fname, added, task)) x), '[]'::jsonb) || app.wall_intel_flags(added, fname);
    else
      f := f || app.wall_code_flags(fname, added, task) || app.wall_intel_flags(added, fname);
    end if;
    -- 082, as an email filter treats attachments: by the file's name (GitHub sends no bytes for a binary file).
    ext := lower(substring(fname from '\.([A-Za-z0-9]{1,8})$'));
    if lower(fname) ~ '\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip|rtf)\.(exe|scr|pif|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|ps1|jar)$'
       or fname ~ '[\u202e\u202d\u200e\u200f]' then
      f := f || jsonb_build_array('W32 disguised file name: ' || left(fname, 120));
    elsif ext = any (array['exe', 'scr', 'pif', 'com', 'vbe', 'wsf', 'wsh', 'hta', 'lnk', 'msi', 'msp', 'cpl', 'apk', 'dll', 'sys', 'dmg', 'pkg', 'deb', 'rpm', 'iso', 'img'])
       and not (cardinality(paths) > 0 and exists (select 1 from unnest(paths) p where lower(p) = lower(fname))) then
      f := f || jsonb_build_array('W31 executable or installer file: ' || left(fname, 120));
    elsif ext = any (array['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'jar', 'war', 'cab']) then
      f := f || jsonb_build_array('W30 archive the Wall can''t open: ' || left(fname, 120));
    end if;
  end loop;
  return f;
end $$;
revoke execute on function app.wall_files_flags(uuid, jsonb) from public;


-- IPv6 threat ranges (087: the simulation found the firewall matched IPv4 only). Spamhaus DROP's IPv6 list, as the
-- IPv4 one. A range must be a real network between /19 and /64; one covering private, link-local, loopback,
-- multicast or a public resolver's range is never blocked (dropped, never an error that loses the run).
create function app.wiki_cidr6_ok(p text) returns boolean
language plpgsql immutable set search_path = pg_catalog as $f$
declare c cidr;
begin
  if coalesce(p, '') !~ '^[0-9a-f:]{2,39}/[0-9]{1,3}$' then return false; end if;
  c := p::cidr;
  return family(c) = 6 and masklen(c) between 19 and 64 and c::text = p;
exception when others then return false;
end $f$;
create function app.wiki_never_block_cidr6(p text) returns boolean
language sql immutable set search_path = pg_catalog as $f$
  select not app.wiki_cidr6_ok(p) or exists (select 1 from unnest(array['fc00::/7', 'fe80::/10', '::/8', 'ff00::/8', '64:ff9b::/96', '2001:4860:4860::/48',
    '2606:4700:4700::/48', '2620:fe::/48', '2620:119:35::/48', '2001:4860::/32']::cidr[]) r where r && p::cidr)
$f$;
revoke execute on function app.wiki_cidr6_ok(text), app.wiki_never_block_cidr6(text) from public;
grant execute on function app.wiki_cidr6_ok(text), app.wiki_never_block_cidr6(text) to dog_work;

alter table app.wiki_indicators drop constraint wiki_indicators_kind_check;
alter table app.wiki_indicators add constraint wiki_indicators_kind_check
  check (kind = any (array['ip', 'cidr', 'cidr6', 'domain', 'url', 'sha256', 'injection', 'injection_flag']));
alter table app.wiki_indicators drop constraint wiki_indicators_check;
alter table app.wiki_indicators add constraint wiki_indicators_check check (case kind
    when 'ip' then value ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
    when 'cidr6' then app.wiki_cidr6_ok(value)
    when 'cidr' then value ~ '^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])/([89]|[12][0-9]|3[0-2])$'
    when 'domain' then char_length(value) <= 253 and value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    when 'url' then value ~ '^https?://[^[:space:]"''<>]+$'
    when 'sha256' then value ~ '^[0-9a-f]{64}$'
    when 'injection' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
    when 'injection_flag' then char_length(value) <= 120 and value ~ '^[!-~]([ -~]*[!-~])?$' and value !~ '  ' and value = lower(value)
    else false end);
reset role;

-- The wiki's write and the firewall's list (dog_work owns them, as in 083 and 086).
grant create on schema app to dog_work;
set local role dog_work;
create or replace function app.wiki_record(p_claim text, p jsonb) returns text
language plpgsql security definer set search_path = pg_catalog as $$
declare
  s record;
  cur record;
  vid uuid;
  ne integer;
  np integer;
  ni integer;
  changed integer;
  why text;
begin
  if app.actor_kind() <> all (array['anon', 'system']) then
    raise exception 'only the site''s timer records the wiki' using errcode = '42501';
  end if;
  select * into s from app.wiki_settings x where x.singleton for update;
  if p_claim is null or s.claim_hash is null or s.claim_until < now() or s.claim_hash <> encode(sha256(convert_to(p_claim, 'UTF8')), 'hex') then
    raise exception 'no wiki claim' using errcode = '42501';
  end if;
  update app.wiki_settings x set claim_hash = null, claim_until = null where x.singleton;
  if p is null or jsonb_typeof(p) <> 'object' or jsonb_typeof(p -> 'entries') <> 'array' or jsonb_typeof(p -> 'packages') <> 'array'
     or jsonb_typeof(coalesce(p -> 'indicators', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p -> 'indicator_groups', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p -> 'sources', '{}'::jsonb)) <> 'object' or octet_length(p::text) > 40000000 then
    raise exception 'bad wiki run' using errcode = '22023';
  end if;
  ne := jsonb_array_length(p -> 'entries');
  np := jsonb_array_length(p -> 'packages');
  -- 086: indicators also come in groups (one kind and source, many values), which keeps a run of 200,000 small.
  ni := jsonb_array_length(coalesce(p -> 'indicators', '[]'::jsonb))
      + coalesce((select sum(jsonb_array_length(g -> 'values')) from jsonb_array_elements(coalesce(p -> 'indicator_groups', '[]'::jsonb)) g
                   where jsonb_typeof(g -> 'values') = 'array'), 0);
  if ne > 20000 or np > 20000 or ni > 400000 then raise exception 'bad wiki run' using errcode = '22023'; end if;
  insert into app.wiki_versions (status, entries, packages, indicators, sources) values ('kept', ne, np, 0, coalesce(p -> 'sources', '{}'::jsonb)) returning id into vid;
  -- Each row is checked by the tables' own limits: one bad row refuses the whole run (nothing half-written).
  insert into app.wiki_entries (version_id, source, ident, title, severity, cwe, kev, published)
    select vid, e ->> 'source', e ->> 'ident', left(e ->> 'title', 300), e ->> 'severity', e ->> 'cwe', coalesce((e ->> 'kev')::boolean, false), (e ->> 'published')::date
      from jsonb_array_elements(p -> 'entries') e
    on conflict do nothing;
  insert into app.wiki_packages (version_id, ecosystem, name, version, advisory)
    select vid, k ->> 'ecosystem', lower(k ->> 'name'), k ->> 'version', k ->> 'advisory' from jsonb_array_elements(p -> 'packages') k
    on conflict do nothing;
  insert into app.wiki_indicators (version_id, kind, value, source, ref)
    select vid, i ->> 'kind', case when i ->> 'kind' = 'url' then app.wall_url_norm(i ->> 'value') else lower(i ->> 'value') end, i ->> 'source', left(i ->> 'ref', 60)
      from jsonb_array_elements(coalesce(p -> 'indicators', '[]'::jsonb)) i
     where not (i ->> 'kind' = 'domain' and (app.wiki_never_block(i ->> 'value') or app.wiki_public_suffix(i ->> 'value')))
       and not (i ->> 'kind' = 'cidr' and app.wiki_never_block_cidr(i ->> 'value'))
       and not (i ->> 'kind' = 'cidr6' and app.wiki_never_block_cidr6(i ->> 'value'))
       and not (i ->> 'kind' = 'ip' and app.wiki_never_block_ip(i ->> 'value'))
       and not (i ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(i ->> 'value') from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(i ->> 'value') from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
    on conflict do nothing;
  -- 083: a source read once a day (Spamhaus asks for no more) is carried over from the active version on the other run.
  if jsonb_typeof(p -> 'carry') = 'array' then
    insert into app.wiki_indicators (version_id, kind, value, source, ref)
      select vid, x.kind, x.value, x.source, x.ref from app.wiki_indicators x join app.wiki_versions v on v.id = x.version_id and v.status = 'active'
       where x.source in (select jsonb_array_elements_text(p -> 'carry')) and x.source = any (array['spamhaus', 'phishtank', 'eset', 'certpl', 'et', 'cins'])
      on conflict do nothing;
  end if;
  insert into app.wiki_indicators (version_id, kind, value, source, ref)
    select vid, g ->> 'kind', case when g ->> 'kind' = 'url' then app.wall_url_norm(x) else lower(x) end, g ->> 'source', left(g ->> 'ref', 60)
      from jsonb_array_elements(coalesce(p -> 'indicator_groups', '[]'::jsonb)) g, jsonb_array_elements_text(g -> 'values') x
     where jsonb_typeof(g -> 'values') = 'array'
       and not (g ->> 'kind' = 'domain' and (app.wiki_never_block(x) or app.wiki_public_suffix(x)))
       and not (g ->> 'kind' = 'cidr' and app.wiki_never_block_cidr(x))
       and not (g ->> 'kind' = 'cidr6' and app.wiki_never_block_cidr6(x))
       and not (g ->> 'kind' = 'ip' and app.wiki_never_block_ip(x))
       and not (g ->> 'kind' = 'url' and app.wiki_never_block(substring(lower(x) from '^https?://(?:[^@/]*@)?([^/:?#]+)')) and substring(lower(x) from '^https?://[^/]+(/[^?#]*)?') in ('', '/'))
    on conflict do nothing;
  update app.wiki_versions v set indicators = (select count(*) from app.wiki_indicators x where x.version_id = vid) where v.id = vid;
  -- The change caps: rows added plus rows dropped, against the active version (packages, then indicators).
  select * into cur from app.wiki_versions v where v.status = 'active';
  if cur.id is not null and cur.packages >= 20 then
    select (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id) a)
         + (select count(*) from (select ecosystem, name, version, advisory from app.wiki_packages where version_id = cur.id
                                   except select ecosystem, name, version, advisory from app.wiki_packages where version_id = vid) b)
      into changed;
    if changed * 100 > cur.packages * s.max_change_pct then
      why := 'refused: ' || changed || ' of ' || cur.packages || ' exact-match rows would change (cap ' || s.max_change_pct || '%)';
    end if;
  end if;
  if why is null and cur.id is not null and cur.indicators >= 20 then
    -- 083 review: a source the active version doesn't have yet (a new feed's first run) isn't counted as change.
    select (select count(*) from (select kind, value from app.wiki_indicators where version_id = vid
                                    and source in (select distinct y.source from app.wiki_indicators y where y.version_id = cur.id)
                                   except select kind, value from app.wiki_indicators where version_id = cur.id) a)
         + (select count(*) from (select kind, value from app.wiki_indicators where version_id = cur.id
                                   except select kind, value from app.wiki_indicators where version_id = vid) b)
      into changed;
    if changed * 100 > cur.indicators * s.max_indicator_change_pct then
      why := 'refused: ' || changed || ' of ' || cur.indicators || ' indicators would change (cap ' || s.max_indicator_change_pct || '%)';
    end if;
  end if;
  if why is not null then
    delete from app.wiki_indicators where version_id = vid;
    delete from app.wiki_packages where version_id = vid;
    delete from app.wiki_entries where version_id = vid;
    update app.wiki_versions v set status = 'refused', reason = why where v.id = vid;
    return 'refused';
  end if;
  update app.wiki_versions v set status = 'kept' where v.status = 'active';
  update app.wiki_versions v set status = 'active' where v.id = vid;
  -- Keep the active version and the two before it; refused runs' records go after 30 days.
  delete from app.wiki_versions v where v.status = 'kept' and v.id not in (select x.id from app.wiki_versions x where x.status = 'kept' order by x.created_at desc, x.id desc limit 2);
  delete from app.wiki_versions v where v.status = 'refused' and v.created_at < now() - interval '30 days';
  return 'active';
end $$;

create or replace function app.wall_edge_addresses() returns jsonb
language sql stable security definer set search_path = pg_catalog as $$
  select jsonb_build_object('version', (select v.id from app.wiki_versions v where v.status = 'active'),
    'firewall_since', (select w.firewall_since from app.wall_settings w where w.singleton),
    'addresses', coalesce((select jsonb_agg(i.value order by i.value) from app.wiki_indicators i join app.wiki_versions v on v.id = i.version_id and v.status = 'active'
                            where i.kind in ('ip', 'cidr', 'cidr6') and i.source <> all (array['cins', 'et'])), '[]'::jsonb))
$$;
reset role;
revoke create on schema app from dog_work;

