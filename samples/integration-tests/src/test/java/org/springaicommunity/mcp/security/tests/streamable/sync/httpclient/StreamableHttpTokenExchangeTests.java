/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.sample.tokenexchange.OAuth2TokenExchangeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

/**
 * End-to-end test for {@link OAuth2TokenExchangeSyncHttpRequestCustomizer} against a
 * Spring Authorization Server instance: a user access token obtained by one client
 * (through the {@code authorization_code} flow) is exchanged by a different client (RFC
 * 8693 token exchange) for a token targeting the MCP server, and the MCP server sees the
 * original user's identity.
 *
 * @author Yeongchan Shin
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = """
				mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
				mcp.server.bind-session=true
				mcp.server.protocol=STREAMABLE
				spring.security.oauth2.client.registration.token-exchange.client-id=token-exchange-client
				spring.security.oauth2.client.registration.token-exchange.client-secret=token-exchange-secret
				spring.security.oauth2.client.registration.token-exchange.authorization-grant-type=urn:ietf:params:oauth:grant-type:token-exchange
				spring.security.oauth2.client.registration.token-exchange.provider=authserver
				""")
@ActiveProfiles("sync")
class StreamableHttpTokenExchangeTests {

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, StreamableHttpWebFluxTransportAutoConfiguration.class,
			AnthropicChatAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, McpClientConfiguration.class })
	static class TokenExchangeConfig {

	}

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new JsonMapper());

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	WebClient webClient = new WebClient();

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	OAuth2AuthorizedClientService authorizedClientService;

	@Autowired
	OAuth2AuthorizedClientManager clientManager;

	@Autowired
	InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	@DisplayName("Exchanges a user token obtained by another client, and calls a tool with the user's identity")
	void exchangesUserTokenAndCallsTool() throws IOException {
		ensureAuthServerLogin();

		// 1. Obtain a user access token through the authorization_code flow, using the
		// "authserver" registration (client id "default-client"). This simulates the
		// token a
		// resource-server MCP host would receive from its gateway. Capture the raw token
		// value.
		var subjectTokenValue = obtainUserAccessToken();
		assertThat(subjectTokenValue).isNotNull();
		assertThat(claims(subjectTokenValue).get("sub")).isEqualTo("test-user");

		// 2. Exchange that token as a *different* client ("token-exchange-client"),
		// using the sample's token-exchange customizer. The user Authentication carries
		// the subject token as a Jwt, mirroring a resource server's
		// JwtAuthenticationToken;
		// the sample sends the token as the subject token and sets
		// subject_token_type=access_token explicitly on the token response client.
		var subjectJwt = Jwt.withTokenValue(subjectTokenValue)
			.header("alg", "RS256")
			.subject("test-user")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plusSeconds(300))
			.build();
		Authentication subjectAuthentication = new TestingAuthenticationToken(subjectJwt, "N/A");

		// The MCP authorization specification requires MCP clients to name the target MCP
		// server in the `resource` parameter (RFC 8707). It is the canonical URI of the
		// MCP
		// server — the streamable endpoint the client actually calls (`/mcp`), and the
		// value
		// an MCP server checks the token's `aud` against once audience validation is
		// enabled.
		var mcpServerResource = this.mcpServerUrl + "/mcp";
		var tokenExchangeClientManager = OAuth2TokenExchangeSyncHttpRequestCustomizer
			.tokenExchangeAuthorizedClientManager(this.clientRegistrationRepository, this.authorizedClientService,
					mcpServerResource);

		var exchangedTokenValue = new AtomicReference<String>();
		var customizer = capturing(exchangedTokenValue,
				new OAuth2TokenExchangeSyncHttpRequestCustomizer(tokenExchangeClientManager, "token-exchange"));

		var transport = HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(this.jsonMapper)
			.httpRequestCustomizer(customizer)
			.build();

		try (var mcpClient = McpClient.sync(transport)
			.transportContextProvider(() -> McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, subjectAuthentication)))
			.build()) {

			var response = mcpClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

			// 3. The MCP server sees the original user, not the exchanging client
			assertThat(response.content()).hasSize(1)
				.first()
				.asInstanceOf(type(McpSchema.TextContent.class))
				.extracting(McpSchema.TextContent::text)
				.isEqualTo("Hello test-user");
		}

		// 4. A real exchange happened: the outgoing token is a new token, not the subject
		// token forwarded, with the user's identity preserved.
		//
		// The `aud` claim is the exchanging client, not the MCP server, because Spring
		// Authorization Server issues `aud` as the client the token was issued to and
		// does
		// not reflect the `resource` parameter into it. Binding the audience to the MCP
		// server is an authorization server concern (resource indicators, or an audience
		// mapper on Keycloak); the MCP server here accepts the token on the shared
		// issuer,
		// as `validateAudienceClaim` defaults to false. See the sample README.
		assertThat(exchangedTokenValue.get()).isNotNull().isNotEqualTo(subjectTokenValue);
		var exchangedClaims = claims(exchangedTokenValue.get());
		assertThat(exchangedClaims.get("sub")).isEqualTo("test-user");
		assertThat(String.valueOf(exchangedClaims.get("aud"))).contains("token-exchange-client");
	}

	/**
	 * Runs the {@code authorization_code} dance with the existing test machinery (the
	 * {@code /tool/call} endpoint and an authorization-code-based MCP client), and
	 * captures the user access token attached by the authorization-code customizer.
	 */
	private String obtainUserAccessToken() throws IOException {
		var subjectTokenValue = new AtomicReference<String>();
		var seedCustomizer = capturing(subjectTokenValue, new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(
				this.clientManager, this.clientRegistrationRepository, "authserver"));

		var seedTransport = HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(this.jsonMapper)
			.httpRequestCustomizer(seedCustomizer)
			.build();

		var seedClient = McpClient.sync(seedTransport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		this.inMemoryMcpClientRepository.addClient("token-exchange-seed", seedClient);

		HtmlPage callToolResponse = this.webClient
			.getPage("http://127.0.0.1:" + this.port + "/tool/call?clientName=token-exchange-seed&toolName=greeter");
		assertThat(callToolResponse.getWebResponse().getContentAsString()).contains("Hello test-user");

		return subjectTokenValue.get();
	}

	/**
	 * Wraps a customizer, capturing the bearer token it attaches.
	 */
	private static McpSyncHttpClientRequestCustomizer capturing(AtomicReference<String> tokenValue,
			McpSyncHttpClientRequestCustomizer delegate) {
		return (builder, method, endpoint, body, context) -> {
			var probe = HttpRequest.newBuilder(endpoint);
			delegate.customize(probe, method, endpoint, body, context);
			probe.build()
				.headers()
				.firstValue(HttpHeaders.AUTHORIZATION)
				.map((header) -> header.substring("Bearer ".length()))
				.ifPresent(tokenValue::set);
			delegate.customize(builder, method, endpoint, body, context);
		};
	}

	private Map<String, Object> claims(String jwt) {
		var payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
		@SuppressWarnings("unchecked")
		Map<String, Object> claims = new JsonMapper().readValue(payload, Map.class);
		return claims;
	}

	private void ensureAuthServerLogin() throws IOException {
		HtmlPage loginPage = this.webClient.getPage(this.authorizationServerUrl);

		if (loginPage.getWebResponse().getStatusCode() == 404) {
			// Already logged in
			return;
		}
		loginPage.<HtmlInput>querySelector("#username").type("test-user");
		loginPage.<HtmlInput>querySelector("#password").type("test-password");
		loginPage.<HtmlButton>querySelector("button").click();
	}

}
