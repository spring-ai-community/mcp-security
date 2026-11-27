# Migration guide

## 0.1.14 -> 0.2.0

### Properties

| 0.1.14                                                                          | 0.2.0                                                      |
|---------------------------------------------------------------------------------|------------------------------------------------------------|
| `spring.ai.mcp.client.authorization.dynamic-client-registration.allow-loopback-addresses` | `spring.ai.mcp.client.authorization.allow-loopback-addresses` |
| -                                                                               | `spring.ai.mcp.client.authorization.cimd.enabled` (default `true`) |

### Client ID Metadata Documents (CIMD) are on by default

With `mcp-client-security-spring-boot`, each MCP connection now uses the client registration named after the
connection, and creates it with CIMD if it does not exist. In 0.1.14, a single registration under
`spring.security.oauth2.client.registration` was used for all connections.

To keep the 0.1.14 behavior, either name your registration after the connection, or turn CIMD off:

```properties
spring.ai.mcp.client.authorization.cimd.enabled=false
```

When both CIMD and DCR are enabled, CIMD is tried first, then DCR.

### Renamed classes

All classes are in `org.springaicommunity.mcp.security.client.sync.oauth2`.

| 0.1.14                                                     | 0.2.0                                                   |
|------------------------------------------------------------|---------------------------------------------------------|
| `http.client.OAuth2DcrHttpClientTransportCustomizer`       | `http.client.OAuth2HttpClientTransportCustomizer`       |
| `http.client.OAuth2CimdHttpClientTransportCustomizer`      | `http.client.OAuth2HttpClientTransportCustomizer`       |
| `http.client.OAuth2DcrSyncAuthorizationErrorHandler`       | `http.client.OAuth2SyncAuthorizationErrorHandler`       |
| `http.client.OAuth2CimdSyncAuthorizationErrorHandler`      | `http.client.OAuth2SyncAuthorizationErrorHandler`       |
| `registration.McpOAuth2DcrClientManager`                   | `registration.McpOAuth2ClientManager`                   |
| `registration.cimd.McpOAuth2CimdClientManager`             | `registration.McpOAuth2ClientManager`                   |
| `registration.DefaultMcpOAuth2DcrClientManager`            | `registration.dcr.DcrMcpOAuth2ClientManager`            |
| `registration.cimd.DefaultMcpOAuth2CimdClientManager`      | `registration.cimd.CimdMcpOAuth2ClientManager`          |
| `registration.ScopeStepUpMcpOAuth2DcrClientManager`        | `registration.ScopeStepUpMcpOAuth2ClientManager`        |
| `registration.DynamicClientRegistrationService`            | `registration.dcr.DynamicClientRegistrationService`     |
| `registration.DynamicClientRegistrationRequest`            | `registration.dcr.DynamicClientRegistrationRequest`     |
| `registration.DynamicClientRegistrationResponse`           | `registration.dcr.DynamicClientRegistrationResponse`    |
| `registration.cimd.ClientAlreadyExistsException`           | `registration.ClientAlreadyExistsException`             |

The constructors are unchanged. To use both CIMD and DCR, wrap them:
`new DelegatingMcpOAuth2ClientManager(cimdClientManager, dcrClientManager)`.

### `McpOAuth2ClientManager` methods

If you implement or call the client manager directly:

| 0.1.14                                                           | 0.2.0                                                                 |
|------------------------------------------------------------------|-----------------------------------------------------------------------|
| `McpOAuth2CimdClientManager#createClient(...)`                   | `McpOAuth2ClientManager#registerClient(...)`                          |
| `McpOAuth2CimdClientManager#updateClient(...)`                   | `McpOAuth2ClientManager#updateScopes(...)`                            |
| `McpOAuth2DcrClientManager#updateMcpClient(...)`                 | `McpOAuth2ClientManager#updateScopes(...)`                            |
| `McpOAuth2DcrClientManager#registerMcpClient(id, url, request)`  | `DcrMcpOAuth2ClientManager#registerClient(id, url, request)`          |
| `McpOAuth2DcrClientManager#registerMcpClient(id, url, header, request)` | `McpOAuth2ClientManager#registerClient(id, url, header, baseUrl)` |

`registerClient` now throws `ClientAlreadyExistsException` when the client exists, and
`ClientRegistrationNotSupportedException` (`CimdNotSupportedException`, `DcrNotSupportedException`) when the
authorization server does not support that registration method.

### `McpClientRegistrationRepository`

Custom implementations must implement `save(ClientRegistration, String resourceId)`, which replaces an existing
registration. `addClientRegistration` is deprecated.

### New: modern protocol (`2026-07-28`)

Nothing to migrate. With Spring AI 2.1+, connections with
`spring.ai.mcp.client.streamable-http.connections.<name>.protocol=MODERN` are secured automatically, through
`OAuth2HttpClientMcpTransportCustomizer`. See the README for manual setup.
