# tinyoidc TODO

Goal: an OIDC **Relying Party** middleware for Go `net/http`. Wrap a handler; anonymous
requests get bounced through an OpenID Provider (Google, or a local test OP) and come back
with a session. We implement no OP endpoints.

Target shape:

- `GET /auth/login?next=/foo` — start the flow
- `GET /auth/callback` — finish the flow
- `POST /auth/logout` — drop the session
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
      cookie signing key.
- [ ] Load from env; never commit the secret.

## Slice 1 — discovery

- [x] `GET {issuer}/.well-known/openid-configuration`, parse into a struct.
      Fields actually needed: `issuer`, `authorization_endpoint`, `token_endpoint`,
      `jwks_uri`, `id_token_signing_alg_values_supported`, `scopes_supported`,
      `token_endpoint_auth_methods_supported`, `userinfo_endpoint`, `end_session_endpoint`.
- [x] Verify the returned `issuer` matches the URL you asked. Mismatch = abort.
- [ ] Cache the document with a TTL. Refresh in the background, never block a login on it.
- [x] Require HTTPS for the issuer, with a localhost/dev escape hatch. Applied to
      `authorization_endpoint`, `token_endpoint` and `jwks_uri` too: `url.Parse` alone
      accepts almost anything, and the `client_secret` goes to `token_endpoint`.
      Deliberately *not* requiring the endpoints to share the issuer's origin — Google's
      issuer is `accounts.google.com` but its token endpoint is `oauth2.googleapis.com`.

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
- [x] Cap the pending store. `/auth/login` is unauthenticated, so without a cap anyone can
      grow the map until the process dies, and the sweep holds the mutex the handlers need.
      Shed load at the cap rather than evicting: evicting lets an attacker break other
      people's logins on demand.
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
- [x] On an unknown `kid`, re-fetch once — keys rotate — but rate-limit that path so a bogus
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
- [x] Table-driven tests with deliberately broken tokens: expired, `alg: none`, HMAC signed
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
- [x] `Middleware`: session present and valid → put claims in the request `Context` and call
      the next handler. Otherwise → stash the destination and redirect to `/auth/login`.
- [x] Only redirect to login for navigation requests. API/XHR requests should get a 401, not a
      302 into Google's HTML.
- [x] Exported accessor for pulling the user out of a request context.
- [x] Redirect to the saved destination — re-validate that it's local before using it.
- [x] `/auth/logout`: clear the cookie, invalidate server-side state. Make it POST, or
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

---

# Part 2: OAuth, the parts OIDC hides

Goal: add the OAuth role we haven't built, a **resource server**. The RP stops throwing away
the access token and uses it to call an API on the user's behalf. Then bind that token to a
key with DPoP, so a stolen token alone is worthless.

Scenario: a notes API. Alice logs in to the example app (the RP), and `/private` shows her
notes, which the app fetches from `cmd/notesapi` with her access token.

```
browser ──cookie──▶ RP (:8192) ──access token + DPoP proof──▶ notesapi (:8193)
                     │  ▲                                       │
                     ▼  │ code, tokens                          │ JWKS
                   AS / OP ◀────────────────────────────────────┘
```

The two tokens must stay separate:
- ID token: `aud` = our `client_id`. It tells the RP who the user is. The RP verifies it, then
  discards it.
- Access token: `aud` = the API. The RP treats it as opaque and carries it to the API.

Never send one where the other belongs.

## Slice 9 — an AS that can do this

Dex won't serve here: it has no custom API scopes, per-API audiences, or DPoP.

- [ ] `panva/node-oidc-provider`, already listed in Slice 8, is the best fit. It has JWT access
      tokens (RFC 9068), resource indicators (RFC 8707), refresh, client credentials, and
      DPoP. It needs a small JS config file under `dev/`. Keycloak also works, but check that
      your version supports DPoP.
- [ ] Register the API as a resource: identifier `http://localhost:8193`, scopes
      `notes:read`, `notes:write`, `notes:export`, and access token format JWT.
- [ ] Register two clients: the existing RP (auth code + PKCE + refresh) and `exporter`
      (client credentials only).
- [ ] Make the RP's issuer, client ID, and client secret configurable instead of `DEV_*`
      constants, so both ASes can be used.

## Slice 10 — resource server (`cmd/notesapi`)

- [ ] `GET /notes` requires `notes:read`. `POST /notes` requires `notes:write`. Store notes
      in memory, keyed by `(iss, sub)`, the same identity key as Slice 5.
- [ ] Parse `Authorization: Bearer <token>`. Missing, or a scheme other than Bearer → 401.
- [ ] Validate the access token (RFC 9068 §4). Reuse `jwks.go`:
  - [ ] signature, with the alg list pinned as in Slice 4
  - [ ] header `typ` is `at+jwt`, which rejects ID tokens by type
  - [ ] `iss` is the AS
  - [ ] `aud` contains **the API's identifier**, not any client's `client_id`
  - [ ] `exp` and `iat` with leeway
  - [ ] `scope` (space-delimited) contains what the route needs
- [ ] Errors per RFC 6750 §3:
  - bad or expired token → `401` + `WWW-Authenticate: Bearer error="invalid_token"`
  - missing scope → `403` + `WWW-Authenticate: Bearer error="insufficient_scope",
    scope="notes:write"`
  - no credentials → `401` + a plain `WWW-Authenticate: Bearer`, with no error code
- [ ] Table-driven tests, in the spirit of Slice 4. Each must fail:
  - an ID token sent as a bearer token
  - an access token for another audience
  - an expired token
  - a token from the wrong issuer
  - a missing scope (403, not 401)
  - `alg: none`
  - a tampered payload

## Slice 11 — the RP as an OAuth client

- [ ] Request `openid email notes:read notes:write offline_access`, plus
      `resource=http://localhost:8193` if the AS uses RFC 8707.
- [ ] Keep `access_token`, `refresh_token`, and the access token's expiry in `ActiveSession`.
      These stay server-side and never reach the browser.
- [ ] Parse the OAuth error JSON from the token endpoint (`error`, `error_description`),
      not just the status code.
- [ ] `/private` fetches `GET /notes` with the access token and renders the result.
- [ ] Refresh grant: when the token is near expiry, or the API returns `invalid_token`, POST
      `grant_type=refresh_token` and retry once. The AS may rotate the refresh token; store
      the new one. Serialize refreshes per session, because two concurrent requests
      refreshing with the same rotating token can get the session revoked.
- [ ] Refresh fails (`invalid_grant`) → end the app session and send the user through
      login again.
- [ ] Decide, and write down, how the app session's lifetime relates to the refresh token's.
      Today the session dies with the ID token's `exp`.

## Slice 12 — client credentials (`cmd/exporter`)

- [ ] POST `grant_type=client_credentials&scope=notes:export` with the exporter's
      credentials. No browser, no user, no ID token.
- [ ] `GET /notes/export` on the API requires `notes:export` and returns every user's notes.
- [ ] Note that `sub` is now a client, not a person. Make sure `GET /notes` can't be
      satisfied by a client-credentials token that happens to have a `sub`.
- [ ] Cache the token until shortly before `exp`; don't fetch a new one per call.

## Slice 13 — DPoP (RFC 9449)

Bearer means that whoever holds the token can use it. With DPoP, the client holds a private
key, the AS binds the token to that key's thumbprint (`cnf.jkt`), and every request carries
a fresh signed proof. A token leaked from a log, a proxy, or the API itself is then useless
without the key.

It matters most for public clients (SPAs, CLIs), where tokens live on the user's device.
For our server-side RP it guards against leaks downstream. Do it here first, then again in
the CLI stretch below.

### The proof

The proof is a JWT sent in the `DPoP:` header, with a new one for every request.
- header: `typ: dpop+jwt`, `alg: ES256`, and `jwk`, the **public** key (never the private
  parts)
- claims:
  - `jti`: random and unique
  - `htm`: HTTP method
  - `htu`: target URI without query or fragment
  - `iat`: issue time
  - `ath`: base64url(SHA-256(access token)), sent to the API but not to the token endpoint
  - `nonce`: only when the server asks for one

### Client side (RP and exporter)

- [ ] Generate an ECDSA P-256 key pair per session (RP) or per process (exporter). The RP
      keeps it in `ActiveSession`, next to the tokens it binds.
- [ ] `makeProof(method, uri, accessToken string) string`
- [ ] Implement the RFC 7638 JWK thumbprint yourself: SHA-256 over the canonical JSON
      `{"crv":…,"kty":…,"x":…,"y":…}`, with members in lexicographic order and no
      whitespace. Compare it against `cnf.jkt` in a test.
- [ ] Check `dpop_signing_alg_values_supported` in the AS metadata.
- [ ] Optional: send `dpop_jkt=<thumbprint>` in the authorization request (§10) to bind the
      **code** to the key too.
- [ ] Token request, including refresh: add a `DPoP:` header. Expect
      `"token_type": "DPoP"` in the response. If you asked for DPoP and got `Bearer`,
      treat it as an error rather than silently downgrading.
- [ ] API calls: send `Authorization: DPoP <token>` (not `Bearer`) plus `DPoP: <proof with ath>`.
- [ ] Nonces:
  - the AS answers `400 {"error":"use_dpop_nonce"}` + a `DPoP-Nonce` header
  - the RS answers `401` + `WWW-Authenticate: DPoP error="use_dpop_nonce"` + a `DPoP-Nonce`
    header
  - in either case, rebuild the proof with `nonce` and retry once
  - remember the latest nonce per server

### Resource server side (§4.3, §7)

- [ ] Accept `Authorization: DPoP <token>` and require exactly one `DPoP` header.
- [ ] Validate the proof:
  - [ ] it is a JWT, and `typ` is `dpop+jwt`
  - [ ] `alg` is asymmetric and on our allowlist; reject `none` and HMAC
  - [ ] `jwk` is a public key with no private members
  - [ ] the signature verifies **with the embedded `jwk`**
  - [ ] `htm` equals the request method
  - [ ] `htu` equals the request URI, without query or fragment, and normalized. Behind a
        proxy, use the externally visible URL.
  - [ ] `iat` is within a small window, e.g. ±60s
  - [ ] `jti` has not been seen within that window. Keep a replay cache that expires by
        `iat`, and sweep it like `tidyLoop`.
  - [ ] `ath` equals the base64url SHA-256 of the presented access token
  - [ ] the thumbprint of `jwk` equals the access token's `cnf.jkt`
- [ ] Downgrade defense: a token that has `cnf.jkt` but arrives as `Bearer` → reject.
- [ ] Errors: `401` + `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256"`.
      For `invalid_token` on a DPoP token, use the `DPoP` scheme, not `Bearer`.
- [ ] Optional: issue `DPoP-Nonce` values from the RS and require them, to shrink the
      pre-computed-proof window.

### DPoP tests. Each must fail.

- [ ] Token presented without a proof.
- [ ] Token presented as `Bearer`.
- [ ] Proof signed by a different key than `cnf.jkt` (the stolen-token case).
- [ ] Proof replayed: same `jti` twice.
- [ ] Proof for `GET /notes` used on `POST /notes` (`htm`), and on `/notes/export` (`htu`).
- [ ] Proof with a stale `iat`, and one from the future.
- [ ] `ath` for a different token.
- [ ] Proof with `alg: none`, with HS256, and with private key members in `jwk`.
- [ ] Proof with `typ: JWT`.
- [ ] Two `DPoP` headers.
- [ ] Missing or stale nonce when the RS requires nonces.

## Slice 14 — end to end

- [ ] Extend the Slice 6 harness: RP, notesapi, and the AS all running, with a cookie-jar
      client. Anonymous `GET /private` → login → notes rendered, using DPoP throughout.
- [ ] Steal the access token from the RP's session store, replay it with curl → 401 with
      `invalid_dpop_proof`. This demo is the point of DPoP.
- [ ] Expire the access token → the RP refreshes (with a new proof) and the page still loads.
- [ ] Revoke the refresh token at the AS → the user is sent back to login.

## Stretch

- [ ] A CLI client using the device authorization grant (RFC 8628) and DPoP, with its key
      stored on disk with `0600` permissions. This is the public-client case DPoP was
      designed for.
- [ ] Token exchange (RFC 8693): notesapi calls a downstream API on alice's behalf, with a
      token whose `aud` is the downstream API.
- [ ] Token introspection (RFC 7662) as an alternative to JWT access tokens. Compare what
      the RS can and can't know, and when revocation takes effect.

## Reading, once your version works

- [ ] `coreos/go-oidc/v3` `IDTokenVerifier` — short, and the de facto Go reference. Diff its
      check list against yours.
- [ ] OpenID Connect Core 1.0 §3.1.3.7, "ID Token Validation" — the normative checklist.
- [ ] RFC 6749 §10 and RFC 6819 — OAuth threat model. Explains *why* each check exists.
- [ ] RFC 9700 (OAuth 2.0 Security Best Current Practice) — current guidance on PKCE,
      redirect URI matching, and mix-up.
- [ ] RFC 6750 (bearer token usage) and RFC 9068 (JWT access tokens) — the RS's checklist.
- [ ] RFC 9449 (DPoP), especially §4.3 "Checking DPoP Proofs" and §11 "Security
      Considerations".
- [ ] RFC 7638 (JWK thumbprint) — short; you implement it in Slice 13.

---

## Deliberately not doing

- Implicit flow (`response_type=id_token`) and hybrid flow — legacy, and using them well is
  harder than using code+PKCE.
- Dynamic client registration (RFC 7591).
- `private_key_jwt` / mTLS client authentication.
- Front-channel and back-channel logout.
- Acting as an OP / identity broker. Separate project.
