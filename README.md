# MCP Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-17%2B-orange)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)

Security and Authorization support for Model Context Protocol in Spring AI.

## Table of Contents

- [Overview](#overview)
- [MCP Server Security](#mcp-server-security)
- [MCP Client Security](#mcp-client-security)
- [Authorization Server](#authorization-server)
- [Samples](#samples)

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

Provides OAuth 2.0 resource server capabilities for MCP servers.
This module is compatible with Spring WebMVC-based servers only.

### Usage

To configure, import the dependency in your project.

// TODO: add import instructions for both maven and gradle

Then, configure the security for your project in the usual Spring-Security way, adding the provided configurer.
Create a configuration class, and reference the authorization server's URI.
In this example, we have set the authz server's issuer URI in the well known Spring property
`spring.security.oauth2.resourceserver.jwt.issuer-uri`. This property is not a requirement.

```java

@Configuration
@EnableWebSecurity
class McpServerConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUrl
    ) throws Exception {
        return http
                // Enforce authentication with token on EVERY request
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // Configure OAuth2 on the MCP server
                .with(
                        McpResourceServerConfigurer.mcpServerAuthorization(),
                        (mcpAuthorization) -> {
                            // REQUIRED: the issuerURI
                            mcpAuthorization.authorizationServer(issuerUrl);
                            // OPTIONAL: enforce the `aud` claim in the JWT token.
                            // Not all authorization servers support resource indicators,
                            // so it may be absent.
                            // See RFC 8707 Resource Indicators for OAuth 2.0
                            // https://www.rfc-editor.org/rfc/rfc8707.html
                            mcpAuthorization.validateAUdienceClaim(true);
                        }
                )
                .build();
    }
}
```

### Special case: only secure tool calls

It is also possible to secure the tools only, and not the rest of the MCP Server. For example, both `initialize` and
`tools/list` are made public, but `tools/call` is authenticated. To enable this, update the security configuration:

```java

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // ⚠ enable annotation-driven security
class McpServerConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUrl
    ) throws Exception {
        return http
                // Open every request on the server
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll()) // ⚠
                // Configure OAuth2 on the MCP server
                .with(
                        McpResourceServerConfigurer.mcpServerAuthorization(),
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

    // Note: you can also use Spring Security's @Tool
    @McpTool(name = "greeter", description = "A tool that greets a user, by name")
    @PreAuthorize("isAuthenticated()")
    public String greet(@ToolParam(description = "The name of the user") String name, ToolContext toolContext) {
        return "Hello, " + name + "!";

    }

}
```

Note that you can also access the current authentication directly from the tool method itself, using the thread-local
`SecurityContextHolder`:

```java

@McpTool(name = "greeter", description = "A tool that greets a user, by name")
@PreAuthorize("isAuthenticated()")
public String greet(ToolContext toolContext) {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    return "Hello, " + authentication.getName() + "!";

}
```

### Known limitations

- The deprecated SSE transport is not supported.
  Use [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)
  or [stateless](https://modelcontextprotocol.io/sdk/java/mcp-server#stateless-streamable-http-webmvc). (the link for
  stateless does not work out of the box, reload the page if required)
- WebFlux-based servers are not supported.
- Opaque tokens are not supported. Please use JWT.

## MCP Client Security

Provide OAuth 2 support for MCP clients, with both HttpClient-based clients (from `spring-ai-starter-mcp-client`) and
WebClient-based clients (from `spring-ai-starter-mcp-client-webflux`).
This module supports `McpSyncClient`s only.

### Add to your project

To configure, import the dependency in your project.

// TODO: add import instructions for both maven and gradle

### Authorization flows

For our MCP clients, there are three flows available for obtaining tokens:

- `authorization_code`-based flows. This is the flow that the MCP spec illustrates.
  A user is present, and the MCP client makes HTTP requests using a bearer token on behalf of that user.
- `client_credentials`-based flows. This is not detailed in the spec, but compatible.
  Client credentials is for machine-to-machine use-cases, where there is no human is in the loop.
  The MCP clients makes HTTP request with a token for itself.
- Hybrid flows. In some use-cases, the user might not be present for some MCP client calls, such
  as `initialize` or `tools/list`.
  In that case, the MCP client makes calls with `client_credentials` tokens representing the client itself.
  But the user may be present for `tools/call`, and in that case, the client will use an `authorization_code` token
  representing the user.

🤔 Which flow should I use?

- If there are no user-level permissions, and you want to secure "client-to-server" communication with an access token,
  use the `client_credentials` flow, either with `OAuth2ClientCredentialsSyncHttpRequestCustomizer` or
  `McpOAuth2ClientCredentialsExchangeFilterFunction`.
- If there are user-level permission, AND you configure your MCP clients using Spring Boot properties (such as
  `spring.ai.mcp.client.streamable-http.connections.<server-name>.url=<server-url>`), then, on application startup,
  Spring AI will try to list the tools. And startup happens without a user present. In that specific case, use a hybrid
  flow, with either `OAuth2HybridSyncHttpRequestCustomizer` or `McpOAuth2HybridExchangeFilterFunction`.
- If there are user-level permission, AND you know every MCP request will be made within the context of a user request
  (such as: adding tools manually in the GUI), then use the `authorization_code` flow, with either
  `OAuth2AuthorizationCodeSyncHttpRequestCustomizer` or `McpOAuth2AuthorizationCodeExchangeFilterFunction`.
- If, in your server, only the tool calls are secured, and all tool calls

### Setup for all use-cases

In very case, you need to activate Spring Security's OAuth2 client support.

```properties
# TODO
```

### Use with `spring-ai-starter-mcp-client`

Then, configure the security for your project in the usual Spring-Security way, adding the provided configurer.
Create a configuration class, and reference the authorization server's URI.
In this example, we have set the authz server's issuer URI in the well known Spring property
`spring.security.oauth2.resourceserver.jwt.issuer-uri`. This property is not a requirement.

### Known limitations

TODO

## Authorization Server

TODO

## Samples

TODO

- Mention running the samples
- Mention integration tests

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

TODO: do a pass on all code samples

---

**Note:** This is a community-driven project and is not officially endorsed by Spring AI or the MCP project.