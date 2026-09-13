# tinyoidc TODO

Goal: an OIDC **Relying Party** middleware for Go `net/http`. Wrap a handler; anonymous
requests get bounced through an OpenID Provider (Google, or a local test OP) and come back
with a session. We implement no OP endpoints.

Target shape:

- `GET /auth/login?next=/foo` — start the flow
- `GET /auth/callback` — finish the flow
- `GET /auth/logout` — drop the session
- `Middleware(next http.Handler) http.Handler` — the actual product

---

## Slice 0 — clear the decks

- [x] Delete `authzHandler`, `tokenHandler`, `wellKnownHandler` from `oidc.go`. Those are OP
      endpoints; we're the RP and we *call* them on someone else's server.
- [x] Rename `OidcServer` → something RP-flavored, or drop it and expose middleware plus a
      small demo `main.go` with one protected route and one public route.
- [x] Register a test client and write down `client_id` / `client_secret` / redirect URI.
      Start with a local OP (see Slice 8), not Google.
- [x] Config struct: issuer URL, client ID, client secret, redirect URI, scopes,
      cookie signing key. Load from env; never commit the secret.

## Slice 1 — discovery

- [x] `GET {issuer}/.well-known/openid-configuration`, parse into a struct.
      Fields actually needed: `issuer`, `authorization_endpoint`, `token_endpoint`,
      `jwks_uri`, `id_token_signing_alg_values_supported`, `scopes_supported`,
      `token_endpoint_auth_methods_supported`, `userinfo_endpoint`, `end_session_endpoint`.
- [x] Verify the returned `issuer` matches the URL you asked. Mismatch = abort.
- [x] Cache the document with a TTL. Refresh in the background, never block a login on it.
- [x] Require HTTPS for the issuer, with a localhost/dev escape hatch.

## Slice 2 — the authorization request

- [x] Generate per-attempt secrets from `crypto/rand`: `state`, `nonce`, PKCE `code_verifier`.
- [x] PKCE: `code_challenge` = base64url(SHA-256(verifier)), `code_challenge_method=S256`.
- [x] Pending-auth store keyed by `state`, holding `nonce`, `code_verifier`, the post-login
      destination, and a created-at timestamp. **A map, not a single value** — one browser can
      have several logins in flight. Start in-memory with a mutex; note where a shared store
      would go.
- [x] Bind the pending entry to the browser (short-lived cookie holding the state value, or a
      signed cookie carrying the whole entry). An unbound `state` is not a CSRF defense.
- [x] Expire pending entries after ~10 minutes; sweep on a ticker.
- [x] Validate `next` before storing it: must be a relative path on this site. This is where
      open redirects come from.
- [x] Build the redirect URL: `response_type=code`, `client_id`, `redirect_uri` (exact
      registered value, **not** the original destination), `scope=openid email profile`
      (space-delimited), `state`, `nonce`, `code_challenge`, `code_challenge_method`.
- [x] Respond 302 (or 303) to the authorization endpoint.
- [x] Eyeball the generated URL by hand before moving on.

## Slice 3 — the callback

- [x] Handle the error branch first: `?error=access_denied&error_description=...` with no
      `code`. Render something human; do not panic, do not 500.
- [x] Look up `state`. Missing, unknown, expired, or not matching the browser's cookie → reject.
- [x] **Consume the pending entry** — delete it before doing anything else, so a replayed
      callback finds nothing.
- [x] Exchange the code at `token_endpoint`: POST, `application/x-www-form-urlencoded`,
      `grant_type=authorization_code`, `code`, `redirect_uri` (identical to Slice 2),
      `code_verifier`. Do **not** send `state`.
- [x] Client authentication: `client_secret_basic` (HTTP Basic header) by default; pick based
      on `token_endpoint_auth_methods_supported`.
- [x] Parse the JSON response: `access_token`, `token_type`, `expires_in`, `id_token`,
      maybe `refresh_token`, `scope`. Handle the OAuth error JSON body too.
- [x] Timeouts and a bounded response read on the token call.

## Slice 4 — ID token verification (the important one)

- [x] Fetch JWKS from `jwks_uri`; cache it.
- [ ] On an unknown `kid`, re-fetch once — keys rotate — but rate-limit that path so a bogus
      token can't turn into a request flood.
- [x] Select the key by `kid`. Choose the algorithm from the discovery document's supported
      list; **never** take direction from the token's own `alg` header. Reject `none` and
      reject HMAC algorithms outright.
- [x] Verify the signature. Use `go-jose/v4` or `lestrrat-go/jwx/v3` for this — write the
      protocol yourself, not the crypto.
- [x] Claim checks, all of them:
  - [x] `iss` string-equals the discovery `issuer`
  - [x] `aud` contains our `client_id`
  - [x] `azp` equals our `client_id` when `aud` has more than one value
  - [x] `exp` in the future, `iat` sane, small clock-skew allowance (~1–2 min), skew applied
        in both directions
  - [x] `nonce` equals the stored nonce
  - [x] `sub` present and non-empty
- [ ] Table-driven tests with deliberately broken tokens: expired, `alg: none`, HMAC signed
      with the RSA public key as the secret, wrong `aud`, wrong `iss`, wrong `nonce`, unknown
      `kid`, tampered payload, missing `sub`. **Each must fail.** This is the highest-value
      test file in the repo.

## Slice 5 — session and middleware

- [x] Identity key is the pair `(iss, sub)`. Not email. Write down why in a comment.
- [x] If using `email`, require `email_verified == true`.
- [x] Mint an application session independent of the ID token — signed or encrypted cookie,
      or an opaque ID against a server-side store. The ID token is a door check, not a wristband.
- [x] Cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax` (`Strict` breaks the callback),
      `Path=/`, explicit `Max-Age`. Consider the `__Host-` prefix.
- [ ] `Middleware`: session present and valid → put claims in the request `Context` and call
      the next handler. Otherwise → stash the destination and redirect to `/auth/login`.
- [ ] Only redirect to login for navigation requests. API/XHR requests should get a 401, not a
      302 into Google's HTML.
- [ ] Exported accessor for pulling the user out of a request context.
- [ ] Redirect to the saved destination — re-validate that it's local before using it.
- [ ] `/auth/logout`: clear the cookie, invalidate server-side state. Make it POST, or
      CSRF-protect it; a `<img src="/auth/logout">` on any page shouldn't log people out.

## Slice 6 — end-to-end test harness

- [ ] `httptest.Server` for the RP, pointed at a mock OP.
- [ ] `http.Client` with a `cookiejar` and a custom `CheckRedirect` that records every hop.
      ~30 lines and no browser needed.
- [ ] Happy path: anonymous `GET /foo` → lands back on `/foo` authenticated.
- [ ] Negative paths: tampered `state`, replayed `code`, replayed callback, expired pending
      entry, user denies consent, OP returns a 500 at the token endpoint, `next=https://evil`.

## Slice 7 — round it out

- [ ] UserInfo endpoint for claims not in the ID token; verify the `sub` it returns matches.
- [ ] RP-initiated logout via `end_session_endpoint` with `id_token_hint` and
      `post_logout_redirect_uri`.
- [ ] Refresh tokens / `offline_access`, if sessions should outlive the ID token.
- [ ] `prompt`, `max_age`, `login_hint`, and checking `auth_time` for step-up re-auth.
- [ ] Multiple OPs: per-OP config and credentials, encode the chosen OP in `state`, and check
      the RFC 9207 `iss` authorization-response parameter to defend against mix-up.
- [ ] Structured logging for each stage. Never log tokens, codes, or the client secret.

## Slice 8 — test providers

- [ ] `navikt/mock-oauth2-server` — Docker image built as a test double; lets you script
      arbitrary claims and malformed responses. Best first target.
- [x] Dex — small Go OP, static password config. Also worth reading as source.
      Running in podman via `dev/dex/run.sh`; issuer `http://localhost:5556/dex`.
- [ ] `panva/node-oidc-provider` — certified; good for exercising PKCE enforcement and logout.
- [ ] Keycloak — heavy, but the easy way to test refresh and rich claim mapping end to end.
- [ ] Google last, as the real-world smoke test.
  - [ ] Google `iss` quirk: accept both `https://accounts.google.com` and `accounts.google.com`.
  - [ ] Redirect URI must be `https://` (Google allows `http://` only for localhost).

## Reading, once your version works

- [ ] `coreos/go-oidc/v3` `IDTokenVerifier` — short, and the de facto Go reference. Diff its
      check list against yours.
- [ ] OpenID Connect Core 1.0 §3.1.3.7, "ID Token Validation" — the normative checklist.
- [ ] RFC 6749 §10 and RFC 6819 — OAuth threat model. Explains *why* each check exists.
- [ ] RFC 9700 (OAuth 2.0 Security Best Current Practice) — current guidance on PKCE,
      redirect URI matching, and mix-up.

---

## Deliberately not doing

- Implicit flow (`response_type=id_token`) and hybrid flow — legacy, and using them well is
  harder than using code+PKCE.
- Dynamic client registration (RFC 7591).
- `private_key_jwt` / mTLS client authentication.
- Front-channel and back-channel logout.
- Acting as an OP / identity broker. Separate project.
