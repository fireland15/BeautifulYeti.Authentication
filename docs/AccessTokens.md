# Access Token Management

## Components

* **Auth Service:** This service that is responsible for handling user OIDC flows and securely storing and handling oauth2 access and refresh tokens.
* **API:** An API that needs to access resources protected by the identity provider.
* **Client:** The user's browser, or other end clients (mobile, desktop, etc...)

## OIDC Flow

This service makes use of a authorization code flow.

1. User navigates to `https://auth.service.com/login`.
2. User is redirected to identity provider.
3. User is redirected back to `https://auth.service.com/oidc-callback`
4. The auth service redeems the auth code and receives access, id, and refresh tokens from the identity provider.
5. The auth service generates a unique, random sessionID (32 byte).
6. The auth service encrypts and stores OAuth2 tokens in redis using the sessionID as the key.
7. The sessionID is written to a HTTPOnly, Secure, SameSite=lax cookie named `session` in the callback response.

## Access Token Retrieval

To prevent leaking all tokens to APIs, the auth service exposes a secure endpoint to exchange sessionIDs for access tokens. The auth service handles refresh tokens on behalf of the APIs and should return valid access tokens.

The Auth Service exposes `POST https://auth.service.com/access-token` for this purpose. APIs calling this must include a shared secret in the request header `x-api-key`. This secret can be configured for the auth service by setting the `SHARED_API_KEYS` environment variable prior to startup. The `SHARED_API_KEYS` environment variable should be of the format `name=KEY;name2=KEY2` to enable multiple keys to be used and traced back to specific services.

The request body must contain a JSON object of the shape. The sessionId should be retrieved from the request cookie `session` received from the client. 

```json
{
  "sessionId": "USER_SESSION_ID"
}
```

The Auth Service will validate the request's API key. Invalid key values will return 401 responses. Invalid or non-existent sessionIDs will receive a 404 response. The endpoint is rate limited based on api key. The limits will be tunable through configuration of the `RATE_LIMITS_ACCESS_TOKEN` environment variable which should contain the max number or requests allowed per api-key per minute.

Requests with a valid sessionID will receive a 200 response with a JSON body shaped like:

```json
{
  "accessToken": "abc...123",
  "expires": 123456,
  "sessionId": "xyz789"
}
```

The `accessToken` is a JWT that can be used to call downstream services protected by the identity provider. `expires` is the UTC seconds when the access token will be expired. The Auth Service will automatically use the refresh token to retrieve a new accessToken if the accessToken has expired or is nearing expiration (within 30 sec).

Note: The response body contains a `sessionId` field for future work on rotating sessionIds. The response will contain the current sessionID, but in the future it may contain a new sessionID if it has been rotated. It would be the callers responsibility to update the session cookie with the new sessionID, or retain the value somewhere.

Note: APIs should cache access tokens until expires is reached.

## Access Token Storage

As part of the OIDC login flow, OAuth2 tokens are encrypted and stored in redis under the key `session:{sessionID}:tokens`. The TTL of the redis entry should mirror the expiration of the refresh token. The encryption key for sessions is set via the `ENCRYPTION_KEY` environment variable. The stored tokens should be a JSON encode object of the following shape (although that is an implementation detail).

```json
{
  "access_token": "",
  "refresh_token": "",
  "expiry": 0,
  "id_token": ""
}
```

The Auth Service should be implemented in such a way to avoid race conditions or deadlocks when updating a session's tokens.