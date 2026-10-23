// dog-probe answered its questions on Oct 23, 2026 (OPERATIONS.md) and is switched off.
Deno.serve(() => Response.json({ ok: false, error: "switched off; see OPERATIONS.md" }, { status: 410 }));
