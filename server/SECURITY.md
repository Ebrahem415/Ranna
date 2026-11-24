# رنة live prototype — security review v2 (2026-11-24)

Re-reviewed after hardening round. Status: DONE = implemented and tested; PARTIAL = implemented, needs hardening; MISSING = not implemented.

## Authentication and sessions
- DONE: passwords stored as salted scrypt hashes; never returned in plaintext.
- DONE: session tokens are 192-bit random, stored as SHA-256 hashes in the database (verified: the raw token does not appear in the DB file), expire after 7 days.
- DONE: rate limiting on auth endpoints, tested live: login 10 attempts/5 min per IP (11th attempt returned 429), register 5/10 min, OTP start 5/10 min, OTP verify 15/10 min, contact lookup 10/5 min.
- DONE: phone OTP codes stored hashed, 10-minute expiry, 5-attempt limit; wrong code and expiry paths tested.
- MISSING: password reset/change flows; 2FA for password accounts.

## Transport and headers
- DONE: X-Content-Type-Options: nosniff and no-store on API responses.
- MISSING: HTTPS at the app layer. TLS must be terminated by the host (Railway/Render do this automatically). Do not accept real credentials without TLS.
- MISSING: CSP and HSTS headers (meaningful once behind TLS).

## Data storage
- DONE: moved from JSON file to SQLite (node:sqlite) with WAL mode — atomic, concurrency-safe, indexed; the earlier lost-on-redeploy concern is now about the single .db file, which maps to one small persistent volume on the host.
- MISSING: message retention/deletion controls, account deletion, export.

## Message and view safety
- DONE: messages render via textContent (no HTML injection).
- DONE: fixed a real UI bug caught by screenshot review: `.view` used display:flex which overrode the `hidden` attribute, so all views rendered stacked. Added `.view[hidden]{display:none}`; re-verified via two-session screenshots.
- DONE: message length cap 2000 chars; request body cap 16 KB; username allow-list.
- MISSING: abuse controls (blocking, reporting); attachments not implemented.

## Privacy of contacts
- DONE: the open "all registered users" endpoint is removed (returns 404). Contacts are exact-match lookup by username or phone only, rate-limited; responses contain username + display name only — never the phone number or email (verified in tests). Phone-registered accounts get random usernames so the number is not guessable from the username.
- DONE: conversation lists show only existing conversation partners.

## Phone and Google sign-in
- Phone OTP: fully implemented and tested end-to-end in dev mode (code in server log). Live SMS needs a provider; a genuinely $0 path exists (Twilio trial: no card, messages verified recipient numbers only) but it caps recipients and is not a growth path. Nothing activated.
- Google sign-in: full authorization-code flow implemented, with login-CSRF protection (state cookie vs query param) and verified identity: the id_token signature is verified against Google's published JWKS, plus audience, issuer, and expiry checks, and unverified emails are rejected. Code-reviewed but NOT executable-tested — it needs the app owner's Google Cloud OAuth client first. No claim that it works until that test runs.

## Verdict
The fixable blockers from v1 are closed and test-verified: rate limits, hashed sessions, consistent storage, contacts privacy, view-switching bug. Remaining before real users: TLS (comes with the host), then account deletion and abuse controls. Suitable for a two-person private demo behind TLS; not for open public sign-up.
