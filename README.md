# OIDC

## Relying Party (RP)

Suppose an anonymous client has requested to GET /foo.
 * Server (RP) notices that client is anonymous, presents a login window that includes some popular OPs such as Google
 * <user clicks "log in with Google", yielding a URL >
   (who keeps track of the original destination, GET /foo?)
 * Server GETs https://accounts.google.com/.well-known/openid-configuration, finds .authorization_endpoint --> https://accounts.google.com/o/oauth2/v2/auth
 * Server issues 302 from original request to https://accounts.google.com/o/oauth2/v2/auth with params:
   - state = xxx (from login page)
   - nonce = yyy
   - scope = openid.email.profile
   - redirect_url = (original /foo)
   - response_type = code
   - client_id = <RP identifier>
 * Client invokes that URL with those params
 * Client authenticates with OP
   <successful login>
 * OP redirects to redirect_url from above, with params
   - state = xxx (same as above)
   - code = ???
 * RP POSTs to OP's config's token_endpoint URL, with params
   - client_id, client_secret which RP has pre-registered with OP
   - grant_type = authorization_code
   - code = ??? (from above)
   - state = xxx (same as above)
 * OP generates returns a signed token
 * RP validates signed token against known OP metadata
 (Server (RP) now has a valid token)
 * RP redirects client to their original URL
  
