// The JEVs gateway's entry point in Supabase (GATEWAY.md). It is the only code with a database login.
//   - At start-up it uses Supabase's main login once, to read from Vault what migration 017 made there: the narrow
//     login's password and the site's keys. Every request then runs through the narrow login dog_web, which can only
//     become the site role, through Supabase's transaction pooler (port 6543), encrypted and certificate-checked.
//   - The code it runs is this repository's own (supabase/functions/jevs-gateway/gateway.js, built from the site's
//     sources by scripts/build-gateway.js and checked by test/gateway.test.js), imported at one fixed commit.
//   - The go-live stage, the preview allow-list and GitHub's (public) client ID are written here, so every change to
//     them is a commit anyone can read. Claude changes the stage only on Aaron's words, recorded in OPERATIONS.md.
import postgres from "npm:postgres@3.4.9";
import gateway from "https://cdn.jsdelivr.net/gh/MyChiefOS/start-of-something-great@GATEWAY_COMMIT/supabase/functions/jevs-gateway/gateway.js";
const { handle } = gateway;

const STAGE = "preview";
// Aaron's GitHub account ID (checked on the GitHub API, Oct 23, 2026): during the preview only he can make an account.
const PREVIEW_ALLOW = "github:304218593";
const GITHUB_CLIENT_ID = "";

// Supabase's public root certificate (Supabase Root 2021 CA, valid to 2031; db/certs/supabase-root-2021.crt).
const SUPABASE_CA = `-----BEGIN CERTIFICATE-----
MIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow
azELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD
YXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug
Um9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW
QyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q
DmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2
GtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi
cvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4
O4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt
NaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX
uXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt
aUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU
tVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b
VW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6
jB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx
Cea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2
CMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P
o/bKiIz+Fq8=
-----END CERTIFICATE-----`;

const KEYS = ["dog_web_password", "dog_session_secret", "dog_ip_hash_key", "dog_fingerprint_key_1"];
let booted: Promise<void> | null = null;

async function boot() {
  const main = new URL(Deno.env.get("SUPABASE_DB_URL")!);
  const sql = postgres(main.toString(), { max: 1, prepare: false, onnotice: () => {} });
  let rows: { name: string; decrypted_secret: string }[];
  try {
    rows = await sql`select name, decrypted_secret from vault.decrypted_secrets where name = any(${KEYS})`;
  } finally {
    await sql.end({ timeout: 5 });
  }
  const v = Object.fromEntries(rows.map((r) => [r.name, r.decrypted_secret]));
  if (KEYS.some((k) => !v[k])) throw new Error("the gateway's keys are not all in Vault (migration 017)");
  const db = new URL("postgres://placeholder");
  db.hostname = main.hostname;
  db.port = "6543";
  db.username = "dog_web";
  db.password = v.dog_web_password;
  db.pathname = main.pathname || "/postgres";
  Object.assign(process.env, {
    DOG_GATEWAY: "1",
    DATABASE_URL: db.toString(),
    DATABASE_CA: Deno.env.get("DATABASE_CA") ?? SUPABASE_CA,
    SESSION_SECRET: v.dog_session_secret,
    IP_HASH_KEY: v.dog_ip_hash_key,
    FINGERPRINT_KEY_1: v.dog_fingerprint_key_1,
    GITHUB_CLIENT_ID,
    LAUNCH_STAGE: STAGE,
    LAUNCH_PREVIEW_ALLOW: PREVIEW_ALLOW
  });
}

// A request in the shape the site's handlers expect (the same shape Vercel gives them), and back again.
Deno.serve(async (request) => {
  booted ??= boot().catch((e) => { booted = null; throw e; });
  try {
    await booted;
  } catch {
    return new Response("The gateway is starting; please try again shortly.", { status: 503, headers: { "Cache-Control": "no-store" } });
  }
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => { headers[key] = value; });
  headers.host = "dayonegreat.com";
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : (await request.text()).slice(0, 65536);
  const req = { method: request.method, url: url.pathname + url.search, headers, query: Object.fromEntries(url.searchParams), body };
  const out = new Headers();
  let status = 200;
  let text = "";
  const res = {
    headersSent: false,
    get statusCode() { return status; },
    set statusCode(s: number) { status = s; },
    setHeader(k: string, value: string | string[]) {
      out.delete(k);
      for (const one of ([] as string[]).concat(value)) out.append(k, one);
    },
    getHeader(k: string) {
      return k.toLowerCase() === "set-cookie" ? (out.getSetCookie().length ? out.getSetCookie() : undefined) : (out.get(k) ?? undefined);
    },
    end(b?: string) { text = b ?? ""; res.headersSent = true; }
  };
  await handle(req, res);
  return new Response(request.method === "HEAD" ? null : text, { status, headers: out });
});
