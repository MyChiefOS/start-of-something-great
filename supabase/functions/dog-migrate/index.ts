// dog-migrate is switched off between migrations, so nobody can make it open database connections on demand.
// The runner itself is runner.ts: to apply a new migration, set its COMMIT and FILES, deploy runner.ts as this
// function's entry point, call it once, check the result, then deploy this file again. Every run is logged in
// OPERATIONS.md. Applied so far: 001-017, on Oct 23, 2026, from commit 9b1fcd7.
Deno.serve(() => Response.json({ ok: false, error: "switched off between migrations; see OPERATIONS.md" }, { status: 410 }));
