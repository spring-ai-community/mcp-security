# Sample: MCP client authentication with token exchange (RFC 8693)

This sample shows how an MCP host that is an **OAuth2 resource server** — it receives
and validates the user's bearer token, but never performs the login itself — can call
MCP servers with the **user's identity**, using the
[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693) grant.

## The topology

In many enterprise systems, the MCP host is not the application the user logs into:

```
user
  │  authorization_code + PKCE
  ▼
gateway
  │  user JWT (sub: the user, aud: NOT the MCP server)
  ▼
MCP host
  │  RFC 8693 token exchange
  ▼
exchanged JWT (sub preserved, newly issued for the MCP call)
  │
  ▼
MCP server
```

The host only holds a validated user JWT whose audience is the gateway, not the MCP
server. That token cannot be passed through to the MCP server: the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
requires audience validation and forbids token passthrough. With `client_credentials`,
every call reaches the MCP server as the host itself: per-user authorization, audit
attribution and user-specific policies all stop working.

| How the host authenticates the MCP call | Identity seen by the MCP server |
|------------------------------------------|---------------------------------|
| Forwarding the incoming user JWT          | Rejected — wrong audience       |
| `client_credentials`                      | The host itself                 |
| Token exchange                            | The user                        |

Token exchange solves this: the host sends the incoming user token as the
`subject_token` and receives a newly issued token for the MCP call, with the user's
identity (`sub`) preserved.

Note: this is the single-trust-domain case, where the host and the MCP servers trust
the same authorization server. For the cross-domain case — the MCP server has its own
authorization server, brokered by an enterprise IdP — see the
[enterprise-managed-authorization MCP extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

## The exchange on the wire

Behind `TokenExchangeOAuth2AuthorizedClientProvider`, the host sends a regular token
request to the authorization server:

```
POST /oauth2/token
Authorization: Basic <token-exchange client credentials>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the incoming user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
resource=<the canonical URI of the MCP server>
```

The response contains a new access token. As observed in the integration test:

```
incoming user token            exchanged token
  sub: test-user         ──▶     sub: test-user             (identity preserved)
  aud: default-client            aud: token-exchange-client (newly issued)
```

Token exchange preserves the user's identity but mints a fresh token: the exchanged
token is a new authorization decision made by the authorization server, not a forwarded
credential.

## The resource parameter

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#resource-parameter-implementation)
requires MCP clients to implement [RFC 8707 resource indicators](https://www.rfc-editor.org/rfc/rfc8707):
the `resource` parameter MUST be included in token requests, MUST identify the MCP server
the token is intended for, and MUST be sent **regardless of whether the authorization
server supports it**. `tokenExchangeAuthorizedClientManager(...)` therefore takes the MCP
server's canonical URI and sets it on every exchange.

That canonical URI is what the MCP server derives for itself, not its base URL: with
`validateAudienceClaim` enabled it checks `aud` against
`<scheme>://<host>:<port><contextPath><resourcePath>` computed from the incoming request (so a
server mounted at `/mcp` expects `https://host/mcp`). Behind a reverse proxy, configure the
server to reconstruct the external URL (`ForwardedHeaderFilter`); otherwise it derives its
internal address, `aud` will not match, and the call fails with a 401 that is hard to diagnose
from the client side.

Sending it is the client's part. Acting on it is not:

| Layer | Requirement | In this sample |
|---|---|---|
| MCP client | send `resource` naming the MCP server | done, asserted on the wire |
| Authorization server | reflect `resource` into the token's `aud` | Spring Authorization Server issues `aud` as the client the token was issued to and does not reflect `resource` into it; Keycloak can bind it with an audience mapper |
| MCP server | validate `aud` | `validateAudienceClaim` defaults to `false`, so the token is accepted on the shared issuer |

So the exchanged token here is not audience-bound to the MCP server, which is why the
integration test observes `aud: token-exchange-client`. To bind it, configure the
authorization server to honour resource indicators (or add an audience mapper on Keycloak),
and then enable `validateAudienceClaim(true)` on the MCP server in production.

### One registration per MCP server, per grant type

`AuthorizedClientServiceOAuth2AuthorizedClientManager` loads and saves authorized clients
through the `OAuth2AuthorizedClientService`, which keys them by
`(clientRegistrationId, principalName)`. The `resource` is **not** part of that key.

A `ClientRegistration` therefore corresponds to exactly one MCP server. Sharing one
registration across several MCP servers would serve a token obtained for one server out of
the store when calling another — the token misuse that audience binding exists to prevent.
This is the model the library already assumes: `McpClientRegistrationRepository` resolves the
`resource` of a token request from the registration id. That mapping is populated by dynamic
client registration and by client ID metadata documents, though — registrations declared under
`spring.security.oauth2.client.registration`, as a resource-server host does, are stored with
a `null` resource identifier — so this sample passes the `resource` to the manager instead.

The same applies to the `client_credentials` registration used for protocol requests. With
several MCP servers, register one client per server, per grant type:

```properties
# tools/call, as the user
spring.security.oauth2.client.registration.mcp-tx-orders.client-id=<client-id>
spring.security.oauth2.client.registration.mcp-tx-orders.authorization-grant-type=urn:ietf:params:oauth:grant-type:token-exchange
spring.security.oauth2.client.registration.mcp-tx-orders.provider=<your-provider>

# protocol requests, as the host itself
spring.security.oauth2.client.registration.mcp-orders.client-id=<client-id>
spring.security.oauth2.client.registration.mcp-orders.authorization-grant-type=client_credentials
spring.security.oauth2.client.registration.mcp-orders.provider=<your-provider>
```

and build one manager per token-exchange registration, each with that server's canonical URI
as its `resource`.

Note that the library sends `resource` on `authorization_code` token requests only
(`McpClientOAuth2Configurer`), so tokens obtained through `client_credentials` are not yet
requested for a specific MCP server.

## Usage

Register an OAuth2 client with the token exchange grant:

```properties
spring.security.oauth2.client.registration.token-exchange.client-id=<client-id>
spring.security.oauth2.client.registration.token-exchange.client-secret=<client-secret>
spring.security.oauth2.client.registration.token-exchange.authorization-grant-type=urn:ietf:params:oauth:grant-type:token-exchange
spring.security.oauth2.client.registration.token-exchange.provider=<your-provider>
```

Then wire the customizer into the MCP client transports, so that every outgoing MCP
request exchanges the current user's token before it is sent:

```java
@Configuration
class McpClientSecurityConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) -> syncSpec
            .transportContextProvider(new AuthenticationMcpTransportContextProvider());
    }

    @Bean
    McpSyncHttpClientRequestCustomizer requestCustomizer(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService,
            @Value("${mcp.server.resource}") String mcpServerResource) {
        var manager = OAuth2TokenExchangeSyncHttpRequestCustomizer
            .tokenExchangeAuthorizedClientManager(clientRegistrationRepository, authorizedClientService,
                mcpServerResource);
        return new OAuth2TokenExchangeSyncHttpRequestCustomizer(manager, "token-exchange");
    }

}
```

The incoming user `Authentication` (for example a `JwtAuthenticationToken` populated by
the resource-server support) is picked up from the `McpTransportContext` and used as the
`subject_token` of the exchange.

Set `spring.ai.mcp.client.initialized=false`, as the other samples do, so that
`initialize` and `tools/list` run inside the first user request and are covered by the
exchanged token as well.

When no user authentication is present (for example on background reconnects), the
customizer skips the `Authorization` header by default. For strict multi-tenant setups
where a user-scoped request must never go out without the user's identity, call
`failOnMissingAuthentication(true)` to fail instead.

For long-running, multi-user hosts — where protocol requests and reconnects also happen
outside any user's request — pair this customizer with a `client_credentials`
registration for protocol requests, and use token exchange for `tools/call` only. The
lazy-initialization setup above is the simplest arrangement, and is what the
integration test exercises.

## Subject token type

The host is a resource server acting as the client of a token exchange — the role
[RFC 8693 section 1](https://www.rfc-editor.org/rfc/rfc8693#section-1) describes, and the
scenario its first example walks through. The subject token it holds is an access token
issued by the same authorization server it is calling, which is what
[section 3](https://www.rfc-editor.org/rfc/rfc8693#section-3) defines
`urn:ietf:params:oauth:token-type:access_token` for. The `...:jwt` type is defined for
sending a JWT as an authorization grant to a *different* authorization server (RFC 7523),
which is not what happens here.

`tokenExchangeAuthorizedClientManager(...)` therefore sets `subject_token_type`
explicitly on the token response client:

```java
var accessTokenResponseClient = new RestClientTokenExchangeTokenResponseClient();
accessTokenResponseClient.setParametersCustomizer((parameters) -> parameters
    .set(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token"));

var provider = new TokenExchangeOAuth2AuthorizedClientProvider();
provider.setAccessTokenResponseClient(accessTokenResponseClient);
```

Without that, Spring Security derives `subject_token_type` from the Java type of the
subject token: `TokenExchangeGrantRequest` maps a `Jwt` to `...:jwt` and any other
`OAuth2Token` to `...:access_token`. The subject token resolver only chooses which token
to send — the type identifier comes from that mapping. A resource server holds a `Jwt`, so
the request would go out as `...:jwt`. Spring Authorization Server accepts both types, so
this only surfaces against authorization servers that follow the distinction more strictly:
Keycloak's standard token exchange accepts access tokens only (see the
[Keycloak token exchange guide](https://www.keycloak.org/securing-apps/token-exchange)).
Setting the type explicitly keeps the sample portable across both.

## Keycloak notes

To run this against Keycloak instead of Spring Authorization Server:

- Standard (spec-compliant) token exchange requires **Keycloak 26.2 or later**, and must
  be enabled on the exchanging client with the `standard.token.exchange.enabled: true`
  client attribute.
- Keycloak refuses the exchange unless the exchanging client is an **audience of the
  subject token**. If user tokens are issued to a gateway or frontend client, add an
  audience mapper on those clients that includes the exchanging client's id.

## Tests

`StreamableHttpTokenExchangeTests` in [integration-tests](../integration-tests)
verifies the complete flow: a user token obtained through the `authorization_code` flow
by one client is exchanged by a different client, and the exchanged token is used to
call a tool on a secured MCP server, which responds with the original user's identity.

That test runs against Spring Authorization Server, which accepts both `...:access_token`
and `...:jwt`, so it cannot catch a regression in the subject token type. The unit test
`OAuth2TokenExchangeSyncHttpRequestCustomizerTests.TokenRequestParameters` asserts the token
request on the wire instead: given a `Jwt` subject token, the form body must carry
`subject_token_type=urn:ietf:params:oauth:token-type:access_token`.
