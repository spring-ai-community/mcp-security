# MCP Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-17%2B-orange)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)

Security and Authorization support for Model Context Protocol in Spring AI.

> ⚠️ This project only works Spring AI's 1.1.x branch.

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
This module is compatible with Spring WebMVC-based servers only.

### Add to your project

*Maven*

```xml

<dependencies>

    <dependency>
        <groupId>org.springaicommunity</groupId>
        <artifactId>mcp-server-security</artifactId>
        <version>0.0.6</version>
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
implementation("org.springaicommunity:mcp-server-security:0.0.6")
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
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
                            mcpAuthorization.validateAudienceClaim(true);
                        }
                )
                .build();
    }
}
```

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
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
            @ToolParam(description = "The language for the greeting (example: english, french, ...)") String language
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
        @ToolParam(description = "The language for the greeting (example: english, french, ...)") String language
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
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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

### Known limitations

- The deprecated SSE transport is not supported.
  Use [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)
  or [stateless transport](https://modelcontextprotocol.io/sdk/java/mcp-server#stateless-streamable-http-webmvc). (the
  link for stateless does not work out of the box, reload the page if required)
- WebFlux-based servers are not supported.
- Opaque tokens are not supported. Use JWT.

## MCP Client Security

Provides OAuth 2 support
for [Spring AI's MCP clients](https://docs.spring.io/spring-ai/reference/api/mcp/mcp-client-boot-starter-docs.html),
with both HttpClient-based clients (from `spring-ai-starter-mcp-client`) and
WebClient-based clients (from `spring-ai-starter-mcp-client-webflux`).
This module supports `McpSyncClient`s only.

### Add to your project

*Maven*

```xml

<dependency>
    <groupId>org.springaicommunity</groupId>
    <artifactId>mcp-client-security</artifactId>
    <version>0.0.6</version>
</dependency>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-client-security:0.0.6")
```

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

- If there are user-level permission, AND you know every MCP request will be made within the context of a user request
  (ensure there are no `tools/list` calls on app startup), then use the `authorization_code` flow, with either
  `OAuth2AuthorizationCodeSyncHttpRequestCustomizer` or `McpOAuth2AuthorizationCodeExchangeFilterFunction`.
- If there are no user-level permissions, and you want to secure "client-to-server" communication with an access token,
  use the `client_credentials` flow, with either `OAuth2ClientCredentialsSyncHttpRequestCustomizer` or
  `McpOAuth2ClientCredentialsExchangeFilterFunction`.
- If there are user-level permission, AND you configure your MCP clients using Spring Boot properties (such as
  `spring.ai.mcp.client.streamable-http.connections.<server-name>.url=<server-url>`), then, on application startup,
  Spring AI will try to list the tools. And startup happens without a user present. In that specific case, use a hybrid
  flow, with either `OAuth2HybridSyncHttpRequestCustomizer` or `McpOAuth2HybridExchangeFilterFunction`.

### Setup for all use-cases

In every case, you need to activate Spring Security's OAuth2 client support.
Add the following properties to your `application.properties` file.
Depending on the flow you chose (see above), you may need one or both client registrations:

```properties
# Ensure MCP clients are sync
spring.ai.mcp.client.type=SYNC
# Ensure that you do not initialize the clients on startup
spring.ai.mcp.client.initialized=false
#
#
# For obtaining tokens for calling the tool
# When using the hybrid flow or authorization_code flow, this registers a client
# called "authserver". If using client_credentials, do not include this:
spring.security.oauth2.client.registration.authserver.client-id=<THE CLIENT ID>
spring.security.oauth2.client.registration.authserver.client-secret=<THE CLIENT SECRET>
spring.security.oauth2.client.registration.authserver.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.authserver.provider=authserver
#
# When using the hybrid flow or client_credentials flow, this registers a client
# called "authserver-client-credentials". If using authorization_code, do not include this:
spring.security.oauth2.client.registration.authserver-client-credentials.client-id=<THE CLIENT ID>
spring.security.oauth2.client.registration.authserver-client-credentials.client-secret=<THE CLIENT SECRET>
spring.security.oauth2.client.registration.authserver-client-credentials.authorization-grant-type=client_credentials
spring.security.oauth2.client.registration.authserver-client-credentials.provider=authserver
#
# Both clients above rely on the authorization server, specified by its issuer URI:
spring.security.oauth2.client.provider.authserver.issuer-uri=<THE ISSUER URI OF YOUR AUTH SERVER>
```

Then, create a configuration class, activating the OAuth2 client capabilities with a `SecurityFilterChain`.

```java

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // in this example, the client app has no security on its endpoints
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                // turn on OAuth2 support
                .oauth2Client(Customizer.withDefaults())
                .build();
    }

}
```

If you already have a filter chain configured, ensure that `.oauth2Client(...)` is on.

### Use with `spring-ai-starter-mcp-client`

When using `spring-ai-starter-mcp-client`, the underlying MCP client transport will be based on the JDK's
`HttpClient`.
In that case, you can expose a bean of type `McpSyncHttpClientRequestCustomizer`.
Depending on your [authorization flow](#authorization-flows) of choice, you may use one of the following
implementations:

- `OAuth2AuthorizationCodeSyncHttpRequestCustomizer` (preferred)
- `OAuth2ClientCredentialsSyncHttpRequestCustomizer` (machine-to-machine)
- `OAuth2HybridSyncHttpRequestCustomizer` (last resort)

All these request customizers rely on request and authentication data.
That data is passed through
`McpTransportContext` ([MCP docs](https://modelcontextprotocol.io/sdk/java/mcp-client#adding-context-information)).
To make that information available, you also need to add an `AuthenticationMcpTransportContextProvider` to your MCP Sync
Client.
Tying it all together, taking `OAuth2AuthorizationCodeSyncHttpRequestCustomizer` as an example:

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
            OAuth2AuthorizedClientManager clientManager
    ) {
        // The clientRegistration name, "authserver",
        // must match the name in application.properties
        return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(
                clientManager,
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

All these request customizers rely on request and authentication data.
That data is passed through
`McpTransportContext` ([MCP docs](https://modelcontextprotocol.io/sdk/java/mcp-client#adding-context-information)).
To make that information available, you also need to add an `AuthenticationMcpTransportContextProvider` to your MCP Sync
Client.
Tying it all together, taking `McpOAuth2AuthorizationCodeExchangeFilterFunction` as an example:

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
        // The clientRegistration name, "authserver", must match the name in application.properties
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

If you'd like to modify HTTP requests beyond what MCP Security provide, you can create your own
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

If you'd like to use Spring AI's autoconfiguration altogether, you can create the MCP clients programmatically.
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
- Spring AI autoconfiguration initializes the MCP client app start.
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
It provides a simple configurer for an MCP server.

### Add to your project

*Maven*

```xml

<dependency>
    <groupId>org.springaicommunity</groupId>
    <artifactId>mcp-authorization-server</artifactId>
    <version>0.0.6</version>
</dependency>
```

*Gradle*

```groovy
implementation("org.springaicommunity:mcp-authorization-server:0.0.6")
```

### Usage

Then configure the authorization server (
see [reference documentatio](https://docs.spring.io/spring-security/reference/7.0/servlet/oauth2/authorization-server/getting-started.html#oauth2AuthorizationServer-developing-your-first-application)).
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

This is only an example, and you'll likely want to write your own configuration.
With this configuration, there will be a single user registered (username: `user`, password: `password`).
There will also be a single OAuth2 Client (`default-client-id` / `default-client-secret`).
You can then activate all the authorization server capabilities with the usual Spring Security APIs,
the security filter chain:

```java

@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
