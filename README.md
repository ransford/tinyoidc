# OIDC

## Relying Party (RP)

Suppose OP == Google. As the RP, we've pre-registered with the OP and received a `client_id` and `client_secret`. We also registered our exact `redirect_uri`; the OP only sends codes to allowlisted URIs (exact string match; Google allows `http://` only for localhost).

At startup (and cached), the RP GETs https://accounts.google.com/.well-known/openid-configuration and keeps `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri`.

Suppose an anonymous client has requested to GET /foo.
 * Server (RP) notices that client is anonymous, presents a login window that includes some popular OPs such as Google
 * <user clicks "log in with Google">
 * RP generates per-attempt random values (`crypto/rand`, ~32 bytes, base64url): `state`, `nonce`, PKCE `code_verifier`
 * RP stores `{state, nonce, code_verifier, next=/foo}` bound to this browser (short-lived `HttpOnly` cookie or server-side session). `state` is a CSRF token, not a place to put `/foo`.
 * Server issues 302 to `authorization_endpoint` with params:
   - response_type = code
   - client_id = <RP identifier>
   - redirect_uri = https://my/server/callback (exactly as registered)
   - scope = openid email profile
   - state = xxx
   - nonce = yyy
   - code_challenge = BASE64URL(SHA256(code_verifier)), code_challenge_method = S256
 * Client follows the redirect and authenticates (and consents) at the OP
 * OP redirects client to `redirect_uri` with either
   - `code` + `state`, or
   - `error` (+ `error_description`) + `state`, e.g. if the user denied consent
 * RP checks `state` against the browser-bound value; mismatch or missing → reject. Delete the pending entry so it can't be replayed.
 * RP POSTs to `token_endpoint` (`application/x-www-form-urlencoded`):
   - client auth: HTTP Basic `client_id:client_secret` (`client_secret_basic`, default) or in the body (`client_secret_post`)
   - grant_type = authorization_code
   - code = (from callback)
   - redirect_uri = (identical to above)
   - code_verifier = (from stored entry)
 * OP returns **JSON**: `access_token`, `token_type`, `expires_in`, `id_token` (a JWT), maybe `refresh_token`, `scope`. Only `id_token` is validated by the RP; `access_token` is opaque, for calling APIs like userinfo.
 * RP validates the ID token (OIDC Core §3.1.3.7):
   - JWT is `header.payload.signature`; the header has `alg` and `kid`
   - find the key in the JWKS (from `jwks_uri`, cached) where `.kid` matches; re-fetch once on unknown `kid` (keys rotate)
   - `alg` must be one we expect (e.g. RS256); never `none`, never HMAC
   - check the signature against that key
   - `iss` equals discovery `issuer` (Google quirk: may also be `accounts.google.com`)
   - `aud` contains our `client_id`; if multiple audiences, `azp` == `client_id`
   - `exp` is in the future, `iat` sane (allow ~1–2 min clock skew)
   - `nonce` equals the stored value
 * RP now knows who the user is: identity key is (`iss`, `sub`), not `email`. If using `email`, require `email_verified`.
 * RP creates its **own** session (cookie), independent of the ID token
 * RP redirects client to `next` (/foo), after checking it's a local path (no open redirects)

## PKCE

Recommended even for confidential clients (RFC 9700). Defends against authorization code interception.
 * Authorization request: `code_challenge = BASE64URL(SHA256(code_verifier))`, `code_challenge_method = S256`
 * Token request: `code_verifier`; the OP hashes it and compares

## Mix-up defense (RFC 9207)

If the OP supports it (`authorization_response_iss_parameter_supported`), the callback also carries `iss`; check it matches. Matters when supporting multiple OPs.

# Testing

[Dex](https://dexidp.io/) runs locally as a test OP in podman:

```sh
dev/dex/run.sh   # idempotent; (re)starts the `dex` container
go run ./cmd/example
```

Notes:
 * Storage is in-memory: restarting Dex invalidates codes, tokens, and signing keys.
 * `skipApprovalScreen: true` skips consent. Set it to `false` to test the `error=access_denied` path.
 * Stop it with `podman rm -f dex`.
