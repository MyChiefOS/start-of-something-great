// The public log's key, pinned in the repository (the independent review of Nov 5, H1). Written by
// tools/verify/pin-key.mjs once migration 038 has made the key in production, and changed only by a reviewed pull request,
// so the browser, the command line and the witness all know the log's key without asking the site. null until then: the
// verifier then confirms the key against the witness's pin on GitHub, and says "Key not confirmed" if it can't.
export const PINNED_VKEY = null;
