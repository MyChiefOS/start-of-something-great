// dog-pay (061): the only code that talks to Stripe. Two addresses, neither takes a token (control 8: the site's Vercel
// identity token goes only to the key broker):
//   POST .../dog-pay/tick     "there may be work": no header or body is read. The site and the minute timer poke it.
//   POST .../dog-pay/webhook  Stripe's events, trusted only when Stripe's signature checks.
// Deployed from the merged commit with Supabase's own JWT check off (supabase/config.toml), like the other functions.
// Its secrets are in Supabase Vault and read only here: the restricted Stripe key Aaron pastes once
// (dog_pay_stripe_key), and the two webhook secrets this function makes for itself the first time it runs: one for the
// platform's own events (dog_pay_webhook_secret) and one for the workers' connected accounts, whose account.updated
// says when they can be paid (dog_pay_connect_secret; Stripe sends those only to an endpoint made with connect=true).
// Nothing is logged but the outcome's kind.
import postgres from "npm:postgres@3.4.9";
import { PayError, STRIPE, stripeClient, tick, verifyEvent, webhook } from "./core.mjs";
import { SOURCE_DIGEST } from "./source-digest.mjs";

// Its own address, from Supabase's own setting, so a copy on a branch registers the branch's address.
const SELF = (Deno.env.get("SUPABASE_URL") || "https://nksagchwpyljvjiwolmp.supabase.co") + "/functions/v1/dog-pay";
const EVENTS = ["checkout.session.completed", "checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed",
  "checkout.session.expired", "charge.dispute.created"];
const CONNECT_EVENTS = ["account.updated"];
const MAX_EVENT = 256_000;
const GAP_MS = 2000; // per instance: a burst of pokes opens at most one database connection every 2 seconds
const reply = (status: number, body: unknown) => Response.json(body, { status, headers: { "x-source-digest": SOURCE_DIGEST } });

let lastTick = 0;
let secrets: { key?: string; hook?: string; connect?: string } = {};

// Outbound: Stripe's API host only, no redirects.
const pinned = (url: string, init: RequestInit) => {
  if (new URL(url).origin !== STRIPE) throw new PayError("bad_host");
  return fetch(url, { ...init, redirect: "error" });
};

async function readSecrets(sql: postgres.Sql) {
  if (secrets.key && secrets.hook && secrets.connect) return secrets;
  const rows = await sql`select name, decrypted_secret as v from vault.decrypted_secrets where name = any(${["dog_pay_stripe_key", "dog_pay_webhook_secret", "dog_pay_connect_secret"]})`;
  const m = Object.fromEntries(rows.map((r) => [r.name, r.v]));
  secrets = { key: m.dog_pay_stripe_key, hook: m.dog_pay_webhook_secret, connect: m.dog_pay_connect_secret };
  return secrets;
}

// The first run makes Stripe's webhook endpoint for this function and keeps its secret in Vault, so nobody handles it.
async function ensureWebhooks(sql: postgres.Sql, stripe: ReturnType<typeof stripeClient>) {
  if (!secrets.hook) {
    const ep = await stripe.call("POST", "/v1/webhook_endpoints", { url: SELF + "/webhook", enabled_events: EVENTS,
      description: "Day One Great dog-pay: platform events" }, "webhook-endpoint-platform-v1");
    if (!ep.secret) throw new PayError("webhook_secret_not_returned");
    await sql`select vault.create_secret(${ep.secret}, 'dog_pay_webhook_secret', 'Stripe webhook signing secret for dog-pay platform events, made by dog-pay itself')`;
    secrets.hook = ep.secret;
  }
  if (!secrets.connect) {
    const ep = await stripe.call("POST", "/v1/webhook_endpoints", { url: SELF + "/webhook", enabled_events: CONNECT_EVENTS, connect: true,
      description: "Day One Great dog-pay: workers' connected accounts" }, "webhook-endpoint-connect-v1");
    if (!ep.secret) throw new PayError("webhook_secret_not_returned");
    await sql`select vault.create_secret(${ep.secret}, 'dog_pay_connect_secret', 'Stripe webhook signing secret for dog-pay connected-account events, made by dog-pay itself')`;
    secrets.connect = ep.secret;
  }
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return reply(405, { ok: false, error: "POST only" });
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const isTick = path.endsWith("/tick"), isHook = path.endsWith("/webhook");
  if (!isTick && !isHook) return reply(404, { ok: false, error: "not found" });
  if (isTick) {
    if (Date.now() - lastTick < GAP_MS) return reply(202, { ok: true, skipped: "busy" });
    lastTick = Date.now();
  }
  let body = "";
  if (isHook) {
    if (Number(req.headers.get("content-length") || "0") > MAX_EVENT) return reply(413, { ok: false, error: "too large" });
    body = await req.text();
    if (body.length > MAX_EVENT) return reply(413, { ok: false, error: "too large" });
  }
  const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false, idle_timeout: 5, connect_timeout: 5, onnotice: () => {} });
  try {
    const s = await readSecrets(sql);
    if (!s.key) return reply(503, { ok: false, error: "stripe not set up" });
    const stripe = stripeClient(s.key, pinned);
    if (isTick) {
      await ensureWebhooks(sql, stripe);
      await tick(sql, stripe);
      return reply(200, { ok: true }); // nothing about the work: anyone can call this address
    }
    const ev = await verifyEvent([s.hook!, s.connect!], req.headers.get("stripe-signature"), body);
    return reply(200, await webhook(sql, stripe, ev));
  } catch (e) {
    if (e instanceof PayError && e.status && e.status < 500) return reply(e.status, { ok: false, error: e.code });
    return reply(500, { ok: false, error: "dog-pay failed (" + String((e as { code?: string }).code || (e as Error).name || "error").slice(0, 32) + ")" });
  } finally {
    await sql.end({ timeout: 5 });
  }
});
