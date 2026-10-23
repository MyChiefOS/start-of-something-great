// Probe for the JEVs gateway's database path. Reports only the shape of the connection (host, port, user name
// pattern; never a password) and whether the narrow login dog_web can sign in with its Vault password and become
// dog_app. Switched off after use.
import postgres from "npm:postgres@3.4.9";

Deno.serve(async () => {
  const out: Record<string, unknown> = {};
  const main = new URL(Deno.env.get("SUPABASE_DB_URL")!);
  out.host = main.hostname; out.port = main.port; out.user_pattern = main.username.replace(/[A-Za-z0-9]{20}$/, "<ref>");
  out.has_pooler_style_user = main.username.includes(".");
  const admin = postgres(main.toString(), { max: 1, prepare: false, onnotice: () => {} });
  let pw = "";
  try {
    const [r] = await admin`select decrypted_secret from vault.decrypted_secrets where name = 'dog_web_password'`;
    pw = r ? r.decrypted_secret : "";
    out.vault_password_found = pw.length > 0;
  } catch (e) { out.vault_error = String((e as Error).message).slice(0, 120); }
  finally { await admin.end({ timeout: 5 }); }
  for (const [label, port] of [["direct", main.port], ["pooler_6543", "6543"]] as const) {
    const u = new URL(main.toString());
    u.username = main.username.includes(".") ? "dog_web." + main.username.split(".")[1] : "dog_web";
    u.password = pw; u.port = port;
    const web = postgres(u.toString(), { max: 1, prepare: false, connect_timeout: 8, onnotice: () => {} });
    try {
      const r = await web.begin(async (t) => { await t`set local role dog_app`; return t`select current_user as u, session_user as s`; });
      out[label] = "ok: " + r[0].s + " -> " + r[0].u;
    } catch (e) { out[label] = "error: " + String((e as Error).message).slice(0, 160); }
    finally { await web.end({ timeout: 5 }); }
  }
  pw = "";
  return Response.json(out);
});
