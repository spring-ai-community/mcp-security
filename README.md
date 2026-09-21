# MCP Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-17%2B-orange)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)

Security and Authorization support for Model Context Protocol in Spring AI.

> ⚠️ Versions 0.1.x of `mcp-security` only work Spring AI's 2.0.x branch. For Spring AI 1.1.x, use version `0.0.6`.

## Table of Contents

- [Overview](#overview)
- [MCP Server Security](#mcp-server-security)
- [MCP Client Security](#mcp-client-security)
- [Authorization Server](#authorization-server)
- [Samples](#samples)
- [Integrations](#integrations) (Cursor, Claude Desktop, ...)
- [License](#license)

## Overview

This repository provides
[Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) support for
Spring AI integrations with the Model Context Protocol (MCP). It covers both MCP Clients, MCP Servers, and Spring
Authorization Server.

The project enables developers to:

- Secure MCP servers with OAuth 2.0 authentication
- Configure MCP clients with OAuth 2.0 authorization flows
- Set up authorization servers specifically designed for MCP workflows
- Implement fine-grained access control for MCP tools and resources

## MCP Server Security

Provides OAuth 2.0 resource server capabilities
for [Spring AI's MCP servers](https://docs.spring.io/spring-ai/reference/api/mcp/mcp-server-boot-starter-docs.html).
It also provides basic support for API-key based servers.
OAuth2 and API-key authentication are compatible with Spring WebMVC-based servers only.
[Origin validation](#origin-validation) additionally supports Spring WebFlux.

### Quick start with `mcp-server-security-spring-boot` (recommended)

The easiest way to add OAuth2 security to your MCP server is with the Boot auto-configuration module.
It provides a default `SecurityFilterChain` that secures all endpoints, with no additional configuration
required beyond setting the issuer URI.

*Maven*

```xml

<dependencies>

    <dependency>
        <groupId>org.springaicommunity</groupId>
        <artifactId>mcp-server-security-spring-boot</artifactId>
        <version>0.1.14</version>
    </dependency>

</dependencies>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-server-security-spring-boot:0.1.14")
```

Then configure your `application.properties`:

```properties
spring.ai.mcp.server.name=my-cool-mcp-server
spring.ai.mcp.server.protocol=STREAMABLE

# The issuer URI of the authorization server
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000
```

That's it. When `spring.security.oauth2.resourceserver.jwt.issuer-uri` is set, the auto-configuration
creates a `SecurityFilterChain` that secures all endpoints using the `McpServerOAuth2Configurer`.

For a complete working example, see the
[sample-mcp-server](https://github.com/spring-ai-community/mcp-security/tree/main/samples/sample-mcp-server) module.

### Manual setup with `mcp-server-security`

If you prefer wiring beans yourself (e.g. for advanced customization, API key support, or non-Boot use-cases),
you can use the lower-level `mcp-server-security` module directly.

*Maven*

```xml

<dependencies>

    <dependency>
        <groupId>org.springaicommunity</groupId>
        <artifactId>mcp-server-security</artifactId>
        <version>0.1.14</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- OPTIONAL -->
    <!-- If you would like to use OAuth2, ensure you import the Resource Server dependencies -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

</dependencies>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-server-security:0.1.14")
implementation("org.springframework.boot:spring-boot-starter-security")

// OPTIONAL
// If you would like to use OAuth2, ensure you import the Resource Server dependencies
implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
```

### Usage: OAuth2

Ensure that MCP server is enabled in your `application.properties`:

```properties
spring.ai.mcp.server.name=my-cool-mcp-server
# Supported protocols: STREAMABLE, STATELESS
spring.ai.mcp.server.protocol=STREAMABLE
```

Then, configure the security for your project in the usual Spring-Security way, adding the provided configurer.
Create a configuration class, and reference the authorization server's URI.
In this example, we have set the authz server's issuer URI in the well known Spring property
`spring.security.oauth2.resourceserver.jwt.issuer-uri`.
Using this exact name is not a requirement, and you may use a custom property.

```java

@Configuration
@EnableWebSecurity
class McpServerConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUrl;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http
                // Enforce authentication with token on EVERY request
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // Configure OAuth2 on the MCP server
                .with(
                        McpServerOAuth2Configurer.mcpServerOAuth2(),
                        (mcpAuthorization) -> {
                            // REQUIRED: the issuerURI
                            mcpAuthorization.authorizationServer(issuerUrl);

                            // OPTIONAL: enforce the `aud` claim in the JWT token.
                            // Not all authorization servers support resource indicators,
                            // so it may be absent. Defaults to `false`.
                            // See RFC 8707 Resource Indicators for OAuth 2.0
                            // https://www.rfc-editor.org/rfc/rfc8707.html
                            //
                            // mcpAuthorization.validateAudienceClaim(true);

                            // OPTIONAL: bind the MCP session to the user's identity
                            // This ensures that a session created by a user can only be accessed by that user
                            //
                            // mcpAuthorization.sessionBinding(Customizer.withDefaults());
                        }
                )
                .build();
    }
}
```

### Multi-tenant OAuth2 resource servers

For authorization servers that use a different issuer for each tenant, configure the lower-level
`mcp-server-security` module manually. Supply Spring Security's tenant-aware
`AuthenticationManagerResolver<HttpServletRequest>` and advertise every trusted issuer in the protected resource
metadata:

```java

@Configuration
@EnableWebSecurity
class McpServerConfiguration {

    private static final List<String> TRUSTED_ISSUERS = List.of(
            "https://keycloak.example.com/realms/tenant-a",
            "https://keycloak.example.com/realms/tenant-b"
    );

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        var authenticationManagerResolver =
                JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(TRUSTED_ISSUERS);

        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .with(
                        McpServerOAuth2Configurer.mcpServerOAuth2(),
                        (mcpAuthorization) -> mcpAuthorization
                                .authorizationServers(TRUSTED_ISSUERS)
                                .authenticationManagerResolver(authenticationManagerResolver)
                )
                .build();
    }
}
```

Only explicitly trusted issuers should be accepted. Using an unrestricted issuer predicate would allow arbitrary
issuers to make the server contact attacker-controlled authorization-server endpoints.

If the application already has a tenant-aware `JwtDecoder`—for example, one backed by a
`JWTClaimsSetAwareJWSKeySelector`—pass it to `.jwtDecoder(...)` instead of configuring an
`AuthenticationManagerResolver`.

The `mcp-server-security-spring-boot` auto-configuration remains intended for the single-issuer case. Defining the
`SecurityFilterChain` above makes Boot back off from its default security configuration.

### Special case: only secure tool calls with OAuth2

It is also possible to secure the tools only, and not the rest of the MCP Server. For example, both `initialize` and
`tools/list` are made public, but `tools/call` is authenticated.
To enable this, update the security configuration, turn on method security and requests to `/mcp` are allowed:

```java

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // ⬅️ enable annotation-driven security
class McpServerConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUrl;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http
                // ⬇️ Open every request on the server
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/mcp").permitAll();
                    auth.anyRequest().authenticated();
                })
                // Configure OAuth2 on the MCP server
                .with(
                        McpServerOAuth2Configurer.mcpServerOAuth2(),
                        (mcpAuthorization) -> {
                            // REQUIRED: the issuerURI
                            mcpAuthorization.authorizationServer(issuerUrl);
                        }
                )
                .build();
    }
}
```

Then, secure your tool calls using the `@PreAuthorize` annotation,
using [method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html).
Inside the annotation, you can apply
a [security-based SpEL expression](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html#using-authorization-expression-fields-and-methods).
At the most basic level, you can use `isAuthenticated()`, ensuring that the MCP client sent a request with a valid
bearer token:

```java

@Service
public class MyToolsService {

    // Note: you can also use Spring AI's @Tool
    @PreAuthorize("isAuthenticated()")
    @McpTool(name = "greeter", description = "A tool that greets you, in the selected language")
    public String greet(
            @McpToolParam(description = "The language for the greeting (example: english, french, ...)") String language
    ) {
        if (!StringUtils.hasText(language)) {
            language = "";
        }
        return switch (language.toLowerCase()) {
            case "english" -> "Hello you!";
            case "french" -> "Salut toi!";
            default -> "I don't understand language \"%s\". So I'm just going to say Hello!".formatted(language);
        };
    }

}
```

Note that you can also access the current authentication directly from the tool method itself, using the thread-local
`SecurityContextHolder`:

```java

@McpTool(name = "greeter", description = "A tool that greets the user by name, in the selected language")
@PreAuthorize("isAuthenticated()")
public String greet(
        @McpToolParam(description = "The language for the greeting (example: english, french, ...)") String language
) {
    if (!StringUtils.hasText(language)) {
        language = "";
    }
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    var name = authentication.getName();
    return switch (language.toLowerCase()) {
        case "english" -> "Hello, %s!".formatted(name);
        case "french" -> "Salut %s!".formatted(name);
        default -> ("I don't understand language \"%s\". " +
                    "So I'm just going to say Hello %s!").formatted(language, name);
    };
}
```

### Usage: API keys

Ensure that MCP server is enabled in your `application.properties`:

```properties
spring.ai.mcp.server.name=my-cool-mcp-server
# Supported protocols: STREAMABLE, STATELESS
spring.ai.mcp.server.protocol=STREAMABLE
```

For this, you'll need to provide your own implementation of `ApiKeyEntityRepository`, for storing `ApiKeyEntity`
objects.
These represent the "entities" which have API keys.
Each entry has an ID, a secret for storing API keys in a secure way (e.g. bcrypt, argon2, ...), as well as a name used
for display purposes.
A sample implementation is available with an `InMemoryApiKeyEntityRepository` along with a default `ApiKeyEntityImpl`.
You can bring your own entity implementation with the in-memory repository.

> ⚠️ The `InMemoryApiKeyEntityRepository` uses on bcrypt for storing the API keys, and, as such, will be computationally
> expensive. It is not suited for high-traffic production use. In that case, you must ship your own
> `ApiKeyEntityRepository`  implementation.

With that, you can configure the security for your project in the usual Spring-Security way:

```java

@Configuration
@EnableWebSecurity
class McpServerConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .with(
                        mcpServerApiKey(),
                        (apiKey) -> {
                            // REQUIRED: the repo for API keys
                            apiKey.apiKeyRepository(apiKeyRepository());

                            // OPTIONAL: name of the header containing the API key.
                            // Here for example, api keys will be sent with "CUSTOM-API-KEY: <value>"
                            // Replaces .authenticationConverter(...) (see below)
                            //
                            // apiKey.headerName("CUSTOM-API-KEY");

                            // OPTIONAL: custom converter for transforming an http request
                            // into an authentication object. Useful when the header is
                            // "Authorization: Bearer <value>".
                            // Replaces .headerName(...) (see above)
                            //
                            // apiKey.authenticationConverter(request -> {
                            //     var key = extractKey(request);
                            //     return ApiKeyAuthenticationToken.unauthenticated(key);
                            // });

                            // OPTIONAL: bind the MCP session to the user's identity
                            // This ensures that a session created with a given API key
                            // can only be used with that API key
                            //
                            // apiKey.sessionBinding(Customizer.withDefaults());
                        }
                )
                .build();
    }

    /**
     * Provide a repository of {@link ApiKeyEntity}.
     */
    private ApiKeyEntityRepository<ApiKeyEntityImpl> apiKeyRepository() {
        //@formatter:off
        var apiKey = ApiKeyEntityImpl.builder()
                .name("test api key")
                .id("api01")
                .secret("mycustomapikey")
                .build();
        //@formatter:on

        return new InMemoryApiKeyEntityRepository<>(List.of(apiKey));
    }

}
```

Then you should be able to call your MCP server with a header `X-API-key: api01.mycustomapikey`.
Requests without an API key receive an HTTP 401 response when no other configured authentication mechanism
authenticates the request. Requests containing an invalid API key also receive an HTTP 401 response.

### Origin validation

MCP servers that listen on localhost are reachable from any web page the user visits, which makes them a target for
DNS rebinding attacks. To mitigate this, the
[MCP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#security-warning)
requires servers to validate the `Origin` header of incoming requests.

Unlike the rest of MCP Server Security, origin validation works on both Spring WebMVC and Spring WebFlux servers.

With `mcp-server-security-spring-boot`, origin validation is **on by default**, and allows local origins only:

```yaml
spring:
  ai:
    mcp:
      server:
        security:
          # Defaults to http://localhost:*, http://127.0.0.1:*, http://[::1]:*, http://[::]:*
          allowed-origins:
            - https://mcp-client.example.com
            - https://another-mcp-client.example.com:*
          # OPTIONAL: also validate the Host header. Not validated by default.
          allowed-hosts:
            - mcp-server.example.com
            - mcp-server.example.com:*
```

Setting `allowed-origins` replaces the defaults, so remember to add back the local origins if you still need them, for
example when developing with the MCP Inspector.

#### WebMVC servers

When wiring things up manually with `mcp-server-security`, validation is **not** enabled unless you configure it, on
either configurer:

```java
http.with(mcpServerOAuth2(), (mcpAuthorization) -> {
    mcpAuthorization.authorizationServer(issuerUrl);

    // OPTIONAL: restrict the Origin header
    mcpAuthorization.allowedOrigins(List.of("https://mcp-client.example.com"));

    // OPTIONAL: restrict the Host header
    mcpAuthorization.allowedHosts(List.of("mcp-server.example.com"));
});

// ... or, for API-key based servers:
http.with(mcpServerApiKey(), (apiKey) -> {
    apiKey.apiKeyRepository(apiKeyRepository());
    apiKey.allowedOrigins(List.of("https://mcp-client.example.com"));
    apiKey.allowedHosts(List.of("mcp-server.example.com"));
});
```

Both origins and hosts support exact matches and wildcard port patterns (`https://example.com:*`, `example.com:*`).
Rejected requests receive a JSON-RPC error body, with an HTTP 403 for a disallowed `Origin` and an HTTP 421 for a disallowed `Host`.
If your server needs to support Cross-Origin requests (CORS), see CORS support in Spring Security
for [servlet](https://docs.spring.io/spring-security/reference/servlet/integrations/cors.html)
applications.


#### WebFlux servers

When wiring things up manually with `mcp-server-security`, add the `OriginValidationWebFilter` to your
`ServerHttpSecurity`:

```java
@Bean
SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    // The second argument is the OPTIONAL Host allowlist; pass null to skip Host validation
    var originValidation = new OriginValidationWebFilter(
            List.of("https://mcp-client.example.com"),
            List.of("mcp-server.example.com"));

    return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
        .addFilterAfter(originValidation, SecurityWebFiltersOrder.CORS)
        .build();
}
```

Both origins and hosts support exact matches and wildcard port patterns (`https://example.com:*`, `example.com:*`).
Rejected requests receive a JSON-RPC error body, with an HTTP 403 for a disallowed `Origin` and an HTTP 421 for a disallowed `Host`.
If your server needs to support Cross-Origin requests (CORS), see CORS support in Spring Security
for [reactive](https://docs.spring.io/spring-security/reference/reactive/integrations/cors.html) applications.

### Known limitations

- The deprecated SSE transport is not supported.
  Use [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)
  or [stateless transport](https://modelcontextprotocol.io/sdk/java/mcp-server#stateless-streamable-http-webmvc). (the
  link for stateless does not work out of the box, reload the page if required)
- WebFlux-based servers are only supported for [origin validation](#origin-validation). OAuth2 and API-key
  authentication require WebMVC.
- Opaque tokens are not supported. Use JWT.

## MCP Client Security

Provides OAuth 2 support
for [Spring AI's MCP clients](https://docs.spring.io/spring-ai/reference/api/mcp/mcp-client-boot-starter-docs.html).
This module supports `McpSyncClient`s only, with HttpClient-based clients (from `spring-ai-starter-mcp-client`) and
WebClient-based clients (from `spring-ai-starter-mcp-client-webflux`).

Key features:

- OAuth2 `authorization_code`, `client_credentials`, and hybrid flows
- Dynamic Client Registration (DCR) with automatic MCP server metadata discovery
- Client ID Metadata Document (CIMD): alternative to DCR where the client hosts its own metadata document
- Scope step-up: automatic re-authorization when the MCP server requires additional scopes
- Spring Boot auto-configuration via `mcp-client-security-spring-boot`

### Quick start with `mcp-client-security-spring-boot` (recommended)

The easiest way to add OAuth2 support to your MCP clients is with the Boot auto-configuration module.

*Maven*

```xml

<dependencies>

    <dependency>
        <groupId>org.springaicommunity</groupId>
        <artifactId>mcp-client-security-spring-boot</artifactId>
        <version>0.1.14</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-starter-mcp-client</artifactId>
    </dependency>

</dependencies>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-client-security-spring-boot:0.1.14")
implementation("org.springframework.ai:spring-ai-starter-mcp-client")
```

Configure your MCP client connections in `application.properties`:

```properties
spring.ai.mcp.client.type=SYNC
spring.ai.mcp.client.initialized=false

# MCP server connections (Spring AI auto-configures these)
spring.ai.mcp.client.streamable-http.connections.my-mcp-server.url=http://localhost:8090

# Enable Dynamic Client Registration (default: false)
spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true
# For development purposes, allow loopback addresses for MCP Servers and Auth Servers (default: false)
spring.ai.mcp.client.authorization.dynamic-client-registration.allow-loopback-addresses=true
```

Then, configure a `SecurityFilterChain` with the provided `McpClientOAuth2Configurer`:

```java

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .with(McpClientOAuth2Configurer.mcpClientOAuth2(), Customizer.withDefaults())
                .csrf(CsrfConfigurer::disable)
                .build();
    }

}
```

This is all you need. The auto-configuration module sets up the following beans:

- `McpClientRegistrationRepository`: a `ClientRegistrationRepository` that also tracks the associated MCP resource
  identifier
- `McpOAuth2ClientManager`: manages Dynamic Client Registration (DCR) and scope step-up
- `UrlValidator`, `McpMetadataDiscoveryService` and `DynamicClientRegistrationService`: infrastructure for DCR
- Various `McpClientConfigurer` to update MCP transports and MCP clients so a token is added on every request

For a complete working example, see the
[sample-mcp-client](https://github.com/spring-ai-community/mcp-security/tree/main/samples/sample-mcp-client) module.

### Manual setup with `mcp-client-security`

If you prefer wiring beans yourself (e.g. for advanced or non-Boot use-cases), you can use the lower-level
`mcp-client-security` module directly.

*Maven*

```xml

<dependency>
    <groupId>org.springaicommunity</groupId>
    <artifactId>mcp-client-security</artifactId>
    <version>0.1.14</version>
</dependency>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-client-security:0.1.14")
```

### Authorization flows

For MCP clients, there are three flows available for obtaining tokens:

- `authorization_code`-based flows. This is the flow that the MCP spec illustrates.
  A user is present, and the MCP client makes HTTP requests using a bearer token on behalf of that user.
- `client_credentials`-based flows. This is not detailed in the spec, but compatible.
  Client credentials is for machine-to-machine use-cases, where there is no human in the loop.
  The MCP client makes HTTP requests with a token for itself.
- Hybrid flows. In some use-cases, the user might not be present for some MCP client calls, such
  as `initialize` or `tools/list`.
  In that case, the MCP client makes calls with `client_credentials` tokens representing the client itself.
  But the user may be present for `tools/call`, and in that case, the client will use an `authorization_code` token
  representing the user.

🤔 Which flow should I use?

- If there are user-level permissions, AND you know every MCP request will be made within the context of a user request
  (ensure there are no `tools/list` calls on app startup), then use the `authorization_code` flow.
- If there are no user-level permissions, and you want to secure "client-to-server" communication with an access token,
  use the `client_credentials` flow.
- If there are user-level permissions, AND you configure your MCP clients using Spring Boot properties (such as
  `spring.ai.mcp.client.streamable-http.connections.<server-name>.url=<server-url>`), then, on application startup,
  Spring AI will try to list the tools. And startup happens without a user present. In that specific case, use a hybrid
  flow.

### Dynamic Client Registration (DCR)

MCP Security supports
[RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html) as described in the
[MCP Authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
When enabled, the flow works as follows:

1. The MCP client sends a request to the MCP server without a token.
2. The server responds with HTTP 401 and a `WWW-Authenticate` header containing the resource metadata URL.
3. The `OAuth2SyncAuthorizationErrorHandler` fetches the protected resource metadata and discovers the authorization
   server.
4. The handler performs dynamic client registration with the authorization server.
5. If the server later responds with HTTP 403 and `insufficient_scope`, the handler requests the additional scopes
   (scope step-up).

DCR is disabled by default in the `mcp-client-security-spring-boot` auto-configuration.
To enable it, set `spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true`.
When disabled, ensure you either have a single `ClientRegistration` registered under
`spring.security.oauth2.client.registration`, or provide your own `OAuth2HttpClientTransportCustomizer` bean.
Scope step-up is still supported when DCR is disabled.

#### URL Validation

As a security measure to prevent Server-Side Request Forgery (SSRF), MCP Security enforces HTTPS for all URLs involved
in the Dynamic Client Registration flow, including the resource metadata URL and the authorization server endpoints.
This validation is provided by the `UrlValidator` interface and its implementation.
For production use-cases, tailor the SSRF checks to your specific network setup with a custom implementation of
`UrlValidator`.

When using `mcp-client-security-spring-boot`, when running in development mode, you may need to allow HTTP urls. You can
explicitly allow HTTP for loopback addresses (like `localhost`, `127.0.0.1`, and `[::1]`) by setting the following
property:

```properties
spring.ai.mcp.client.authorization.dynamic-client-registration.allow-loopback-addresses=true
```

### Client ID Metadata Document (CIMD)

CIMD is an alternative to DCR where the client uses a URL as its `client_id`. This URL points to a JSON
metadata document hosted by the client itself. The authorization server fetches that document when processing
an authorization request.
There is no auto-configuration support for CIMD, so you need to manually declare a filter chain, and add the supporting
beans explicilty.


Add `McpClientOAuth2Configurer` to your security filter chain with CIMD enabled (this is the default):

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .with(new McpClientOAuth2Configurer(), mcp -> mcp.cimd(true))
            .build();
}
```

This registers a filter that serves the client metadata document at `/{registrationId}/client-id-metadata.json`, valid for any `{registrationId}`.

Then declare a `DefaultMcpOAuth2CimdClientManager` bean and use `OAuth2CimdHttpClientTransportCustomizer`
instead of the DCR variant:

```java
@Bean
McpOAuth2CimdClientManager cimdClientManager(
        McpMetadataDiscoveryService discoveryService,
        McpClientRegistrationRepository repo,
        UrlValidator urlValidator) {
    return new DefaultMcpOAuth2CimdClientManager(discoveryService, repo, urlValidator);
}

@Bean
McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> transportCustomizer(
        OAuth2AuthorizedClientManager authorizedClientManager,
        McpClientRegistrationRepository repo,
        McpOAuth2CimdClientManager cimdClientManager) {
    return new OAuth2CimdHttpClientTransportCustomizer(authorizedClientManager, repo, cimdClientManager);
}
```

### Use with `McpClientOAuth2Configurer`

`McpClientOAuth2Configurer` is a Spring Security configurer that sets up OAuth2 client support for MCP,
including authorization request and token request customization (e.g. adding the `resource=` parameter).

You can also use it to pre-register OAuth2 clients for specific MCP servers:

```java

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .with(McpClientOAuth2Configurer.mcpClientOAuth2(), mcpOAuth2 -> {
                    // Pre-register an OAuth2 client for a specific MCP server
                    mcpOAuth2.registerMcpOAuth2Client("my-mcp-server", "http://localhost:8090/mcp");
                    // Optionally set the base URL for redirect URIs
                    // mcpOAuth2.baseUrl("http://localhost:8080");
                })
                .build();
    }

}
```

### Use with `spring-ai-starter-mcp-client` (HttpClient-based)

When using `spring-ai-starter-mcp-client`, the underlying MCP client transport is based on the JDK's
`HttpClient`.

**With auto-configuration (`mcp-client-security-spring-boot`):**
The `OAuth2HttpClientTransportCustomizer` is auto-configured and applies OAuth2 support
(request customization and authorization error handling) to each transport automatically. No extra beans are needed.

**Manual configuration:**
You can expose an `OAuth2HttpClientTransportCustomizer` bean, which configures both the request customizer
and the authorization error handler on each transport:

```java

@Configuration
class McpConfiguration {

    @Bean
    OAuth2HttpClientTransportCustomizer transportCustomizer(
            OAuth2AuthorizedClientManager clientManager,
            ClientRegistrationRepository clientRegistrationRepository,
            McpOAuth2ClientManager mcpOAuth2ClientManager
    ) {
        return new OAuth2HttpClientTransportCustomizer(
                clientManager,
                clientRegistrationRepository,
                mcpOAuth2ClientManager
        );
    }

}
```

By default, the customizer maps each MCP connection name to an OAuth2 client registration with the same name.
You can customize this mapping:

```java
// Use a single registration for all transports
new OAuth2HttpClientTransportCustomizer(clientManager, repo, mcpManager, "my-registration-id");

// Or use a custom resolver function
new OAuth2HttpClientTransportCustomizer(clientManager, repo, mcpManager, transportName -> "prefix-" + transportName);
```

Alternatively, if you do not need DCR or authorization error handling, you can use the lower-level
request customizers directly:

- `OAuth2AuthorizationCodeSyncHttpRequestCustomizer` (user-level tokens)
- `OAuth2ClientCredentialsSyncHttpRequestCustomizer` (machine-to-machine)
- `OAuth2HybridSyncHttpRequestCustomizer` (both)

All request customizers rely on authentication data passed through `McpTransportContext`.
When not using the Boot auto-configuration, you need to add an `AuthenticationMcpTransportContextProvider`:

```java

@Configuration
class McpConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) ->
                syncSpec.transportContextProvider(
                        new AuthenticationMcpTransportContextProvider()
                );
    }

    @Bean
    McpSyncHttpClientRequestCustomizer requestCustomizer(
            OAuth2AuthorizedClientManager clientManager,
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(
                clientManager,
                clientRegistrationRepository,
                "authserver"
        );
    }

}
```

### Use with `spring-ai-starter-mcp-client-webflux`

When using `spring-ai-starter-mcp-client-webflux`, the underlying MCP client transport will be based on a Spring
reactive `WebClient`.
In that case, you can expose a bean of type `WebClient.Builder`, configured with an MCP implementation of
`ExchangeFilterFunction`.
Depending on your [authorization flow](#authorization-flows) of choice, you may use one of the following
implementations:

- `McpOAuth2AuthorizationCodeExchangeFilterFunction` (preferred)
- `McpOAuth2ClientCredentialsExchangeFilterFunction` (machine-to-machine)
- `McpOAuth2HybridExchangeFilterFunction` (last resort)

All these filter functions rely on authentication data passed through `McpTransportContext`.
When not using the Boot auto-configuration, you need to add an `AuthenticationMcpTransportContextProvider`:

```java

@Configuration
class McpConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) ->
                syncSpec.transportContextProvider(
                        new AuthenticationMcpTransportContextProvider()
                );
    }

    @Bean
    WebClient.Builder mcpWebClientBuilder(OAuth2AuthorizedClientManager clientManager) {
        return WebClient.builder().filter(
                new McpOAuth2AuthorizationCodeExchangeFilterFunction(
                        clientManager,
                        "authserver"
                )
        );
    }
}
```

### Use with streaming chat client

When using the `.stream()` method of the chat client, you will be using Reactor under the hood. Reactor does not
guarantee on which thread the work is executed, and will lose thread locals. You need to manually extract the
information and inject it in the Reactor context:

```java
class Example {

    void doTheThing() {
        chatClient
                .prompt("<your prompt>")
                .stream()
                .content()
                // ... any streaming operation ...
                .contextWrite(AuthenticationMcpTransportContextProvider.writeToReactorContext());
    }

}
```

### Customize HTTP requests beyond MCP Security's OAuth2 support

MCP Security's default client support integrates with Spring Security to add OAuth2 support. Essentially, it gets a
token on behalf of the user, and modifies the HTTP request from the Client to the Server, adding that token in an
Authorization header.

If you'd like to modify HTTP requests beyond what MCP Security provides, you can create your own
`McpSyncHttpClientRequestCustomizer` or `ExchangeFilterFunction`.

For HTTP clients:

```java

@Configuration
class McpConfiguration {

    @Bean
    McpSyncHttpClientRequestCustomizer requestCustomizer() {
        return (builder, method, endpoint, body, context) ->
                builder
                        .header("x-custom-header", "custom-value")
                        .header("x-life-the-universe-everything", "42");
    }

}
```

For web clients:

```java

@Configuration
class McpConfiguration {

    @Bean
    WebClient.Builder mcpWebClientBuilder() {
        return WebClient.builder().filter((request, next) -> {
            var newRequest = ClientRequest.from(request)
                    .header("x-custom-header", "custom-value")
                    .header("x-life-the-universe-everything", "42")
                    .build();
            return next.exchange(newRequest);
        });
    }

}
```

There is no way to guarantee on which thread these request customizers will run.
As such, thread-locals are not available in these lambda functions.
If you would like to use thread-locals in this context, use a `McpTransportContextProvider` bean.
It can extract thread-locals and make them available in an `McpTransportContext` object.

For HttpClient-based request customizers, the `McpTransportContext` will be available in the `customize` method. See,
for example, with a Sync client (async works similarly):

```java

@Configuration
class McpConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) -> syncSpec.transportContextProvider(() -> {
            var myThing = MyThreadLocalThing.get();
            return McpTransportContext.create(Map.of("custom-key", myThing));
        });
    }

    @Bean
    McpSyncHttpClientRequestCustomizer requestCustomizer() {
        return (builder, method, endpoint, body, context) ->
                builder.header("x-custom-header", context.get("custom-key"));
    }

}
```

For WebClient-based filter functions, the `McpTransportContext` will be available in the Reactor context, under
`McpTransportContext.KEY`:

```java

@Configuration
class McpConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) -> syncSpec.transportContextProvider(() -> {
            var myThing = MyThreadLocalThing.get();
            return McpTransportContext.create(Map.of("custom-key", myThing));
        });
    }

    @Bean
    WebClient.Builder mcpWebClientBuilder() {
        return WebClient.builder()
                .filter((request, next) ->
                        Mono.deferContextual(reactorCtx -> {
                            var transportCtx = reactorCtx.get(McpTransportContext.class);
                            String customThing = transportCtx.get("custom-key").toString();
                            var newRequest = ClientRequest.from(request)
                                    .header("x-custom-header", customThing)
                                    .build();

                            return next.exchange(newRequest);
                        })
                );
    }

}
```

### Programmatically configure MCP clients

If you'd like to bypass Spring AI's autoconfiguration altogether, you can create the MCP clients programmatically.
The easiest way is to draw some inspiration on the transport
auto-configurations ([HttpClient](https://github.com/spring-projects/spring-ai/blob/main/auto-configurations/mcp/spring-ai-autoconfigure-mcp-client-httpclient/src/main/java/org/springframework/ai/mcp/client/httpclient/autoconfigure/StreamableHttpHttpClientTransportAutoConfiguration.java), [WebClient](https://github.com/spring-projects/spring-ai/blob/main/auto-configurations/mcp/spring-ai-autoconfigure-mcp-client-webflux/src/main/java/org/springframework/ai/mcp/client/webflux/autoconfigure/StreamableHttpWebFluxTransportAutoConfiguration.java))
as well as
the [client auto-configuration](https://github.com/spring-projects/spring-ai/blob/main/auto-configurations/mcp/spring-ai-autoconfigure-mcp-client-common/src/main/java/org/springframework/ai/mcp/client/common/autoconfigure/McpClientAutoConfiguration.java).

All in all, it could look like so:

```java
// For HttpClient-based clients
@Bean
McpSyncClient client(
        ObjectMapper objectMapper,
        McpSyncHttpClientRequestCustomizer requestCustomizer,
        McpClientCommonProperties commonProps
) {
    var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
            .clientBuilder(HttpClient.newBuilder())
            .jsonMapper(new JacksonMcpJsonMapper(objectMapper))
            .httpRequestCustomizer(requestCustomizer)
            .build();

    var clientInfo = new McpSchema.Implementation("client-name", commonProps.getVersion());

    return McpClient.sync(transport)
            .clientInfo(clientInfo)
            .requestTimeout(commonProps.getRequestTimeout())
            .transportContextProvider(new AuthenticationMcpTransportContextProvider())
            .build();
}

//
// -------------------------
//
// For WebClient based clients
@Bean
McpSyncClient client(
        WebClient.Builder mcpWebClientBuilder,
        ObjectMapper objectMapper,
        McpClientCommonProperties commonProperties
) {
    var builder = mcpWebClientBuilder.baseUrl(mcpServerUrl);
    var transport = WebClientStreamableHttpTransport.builder(builder)
            .jsonMapper(new JacksonMcpJsonMapper(objectMapper))
            .build();

    var clientInfo = new McpSchema.Implementation("clientName", commonProperties.getVersion());

    return McpClient.sync(transport)
            .clientInfo(clientInfo)
            .requestTimeout(commonProperties.getRequestTimeout())
            .transportContextProvider(new AuthenticationMcpTransportContextProvider())
            .build();
}
```

You can then add it to the tools available to a chat client:

```java
var chatResponse = chatClient.prompt("Prompt the LLM to _do the thing_")
        .toolCallbacks(new SyncMcpToolCallbackProvider(mcpClient1, mcpClient2, mcpClient3))
        .call()
        .content();
```

### Known limitations

- Spring WebFlux servers are not supported.
- Spring AI autoconfiguration initializes the MCP client on app start.
  Most MCP servers want calls to be authenticated with a token, so you
  need to turn initialization off with `spring.ai.mcp.client.initialized=false`.

Note:

- Unlike the `mcp-server-security` module, the client implementation supports the SSE transport, both with `HttpClient`
  and `WebClient`.

## Authorization Server

Enhances Spring
Security's [OAuth 2.0 Authorization Server support](https://docs.spring.io/spring-security/reference/7.0/servlet/oauth2/authorization-server/index.html)
with the RFCs and features relevant to the MCP authorization spec, such as Dynamic Client Registration and Resource
Indicators.

### Quick start with `mcp-authorization-server-spring-boot` (recommended)

The easiest way to set up an MCP authorization server is with the Boot auto-configuration module.
It provides default `SecurityFilterChain`s that secure all endpoints and configure an MCP authorization server, with no additional configuration required.

*Maven*

```xml

<dependency>
    <groupId>org.springaicommunity</groupId>
    <artifactId>mcp-authorization-server-spring-boot</artifactId>
    <version>0.1.14</version>
</dependency>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-authorization-server-spring-boot:0.1.14")
```


### Manual setup with `mcp-authorization-server`

If you prefer wiring beans yourself (e.g. for advanced customization or non-Boot use-cases), you can use the lower-level `mcp-authorization-server` module directly.

*Maven*

```xml
<dependency>
    <groupId>org.springaicommunity</groupId>
    <artifactId>mcp-authorization-server</artifactId>
    <version>0.1.14</version>
</dependency>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-authorization-server:0.1.14")
```

### Usage

Configure the authorization server properties (see [reference documentation](https://docs.spring.io/spring-security/reference/7.0/servlet/oauth2/authorization-server/getting-started.html#oauth2AuthorizationServer-developing-your-first-application)).
Here is an example `application.yml` for registering a default client:

```yaml
spring:
  application:
    name: sample-authorization-server
  security:
    oauth2:
      authorizationserver:
        client:
          default-client:
            token:
              access-token-time-to-live: 1h
            registration:
              client-id: "default-client"
              client-secret: "{noop}default-secret"
              client-authentication-methods:
                - "client_secret_basic"
                - "none"
              authorization-grant-types:
                - "authorization_code"
                - "client_credentials"
              redirect-uris:
                - "http://127.0.0.1:8080/authorize/oauth2/code/authserver"
                - "http://localhost:8080/authorize/oauth2/code/authserver"
                # mcp-inspector
                - "http://localhost:6274/oauth/callback"
                # claude code
                - "https://claude.ai/api/mcp/auth_callback"
    user:
      # A single user, named "user"
      name: user
      password: password

server:
  servlet:
    session:
      cookie:
        # Override the default cookie name (JSESSIONID).
        # This allows running multiple Spring apps on localhost, and they'll each have their own cookie.
        # Otherwise, since the cookies do not take the port into account, they are confused.
        name: MCP_AUTHORIZATION_SERVER_SESSIONID
```

When using the manual setup, you must configure the authorization server properties as shown above, and then activate the authorization server capabilities with the usual Spring Security APIs in your security filter chain:

```java

@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
            // all requests must be authenticated
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            // enable authorization server customizations
            .with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), withDefaults())
            // enable form-based login, for user "user"/"password"
            .formLogin(withDefaults())
            .build();
}
```

### Dynamic Client Registration (DCR)

By default, the authorization server supports Dynamic Client Registration (DCR).
If you are using the Boot auto-configuration (`mcp-authorization-server-spring-boot`), you can disable it with the following property:

```properties
spring.ai.mcp.authorizationserver.dynamic-client-registration.enabled=false
```

If you are configuring the server manually, you can disable it via the configurer:

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), mcp -> {
                mcp.dynamicClientRegistration(false);
            })
            .build();
}
```

### Client ID Metadata Document (CIMD)

CIMD is an alternative to DCR where the client identifies itself with a URL pointing to a metadata document
it hosts. The authorization server fetches that document to validate the client, instead of relying on a
prior registration.

To enable it, use the `cimd(true)` option in `McpAuthorizationServerConfigurer` (disabled by default):

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), mcp -> {
                mcp.cimd(true);
            })
            .formLogin(withDefaults())
            .build();
}
```

When CIMD is enabled, the authorization server:
- Advertises `client_id_metadata_document` in its authorization server metadata
- Accepts client_id URLs and fetches the corresponding metadata document to look up the client

You also need to declare a `ClientIdMetadataDocumentRegisteredClientRepository` bean, which is responsible
for fetching and validating the remote metadata document. If you also want to support traditionally registered
clients (pre-registered or DCR) alongside CIMD, wrap both in a `DelegatingRegisteredClientRepository`.

```java
@Bean
ClientIdMetadataDocumentRegisteredClientRepository cimdClientRepository() {
    var repository = new ClientIdMetadataDocumentRegisteredClientRepository();
    repository.setMetadataDocumentResolver(new DefaultClientIdMetadataDocumentResolver());
    // Set allowLoopback=true in development to accept http://localhost URLs
    repository.setMetadataValidator(new DefaultClientMetadataValidator(new DefaultUrlValidator(false)));
    repository.setClientIdUrlValidator(new ClientIdUrlValidator(false));
    return repository;
}
```

The authorization server validates the redirect URI in an authorization request against
the redirect URIs from the client metadata document. Some clients, such as Claude Code, use a dynamic port with
the `localhost` host. To support those clients, configure `LocalhostWildcardPortValidator`
alongside Spring Authorization Server's default scope validator:

```java
@Bean
SecurityFilterChain securityFilterChain(
        HttpSecurity http) {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), mcp -> {
                mcp.cimd(true);
                mcp.authorizationCodeRequestValidator(
                        new LocalhostWildcardPortValidator()
                                .andThen(DEFAULT_SCOPE_VALIDATOR));
            })
            .formLogin(withDefaults())
            .build();
}
```

### Known limitations

- Spring WebFlux servers are not supported.
- Every client supports ALL `resource` identifiers.

## Samples

The `samples` directory contains samples for these libraries.
A [README.md](https://github.com/spring-ai-community/mcp-security/tree/main/samples) contains instructions for running
those samples.

A special directory is `samples/integration-tests`, which contains integration tests for all the submodules in this
project.

## Integrations

This is a work-in-progress, but with `mcp-server-security`, and a supporting `mcp-authorization-server`, you should be
able to integrate with Cursor, Claude Code, and the MCP inspector.

Note: if you use the MCP Inspector you may need to turn off CSRF and CORS protection.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Note:** This is a community-driven project and is not officially endorsed by Spring AI or the MCP project.
