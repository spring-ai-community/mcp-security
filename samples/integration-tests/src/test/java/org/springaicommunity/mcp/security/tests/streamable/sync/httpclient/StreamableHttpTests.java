package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.spec.McpSchema;
import java.io.IOException;
import java.net.http.HttpClient;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2ClientCredentialsSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HybridSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.UriComponentsBuilder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

/**
 * Note: Here specify the main configuration class so that nested tests know which
 * configuration to pick up. Otherwise, configuration scanning does not find the nested
 * config class in {@link Nested} tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer")
@ActiveProfiles("sync")
class StreamableHttpTests {

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	WebClient webClient = new WebClient();

	@Autowired
	private InMemoryClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@Autowired
	private OAuth2AuthorizedClientManager clientManager;

	@Autowired
	private InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	@DisplayName("When the user is not present and there is no access token, cannot initialize")
	void whenNoTokenThenCannotInitialize() {
		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.objectMapper(new ObjectMapper())
			.clientBuilder(HttpClient.newBuilder())
			.build();
		var mcpClientBuilder = McpClient.sync(transport)
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			assertThatThrownBy(mcpClient::initialize).hasMessage("Client failed to initialize by explicit API call")
				.rootCause()
				// Note: this should be better handled by the Java-SDK.
				// Today, the HTTP 401 response is wrapped in a RuntimeException with
				// a poor String representation.
				.isInstanceOf(RuntimeException.class)
				.hasMessageStartingWith("Failed to send message: DummyEvent");
		}
		catch (Exception e) {
			fail(e);
		}
	}

	@Test
	@DisplayName("When no user is present, can use client_credentials and get a token")
	void whenClientCredentialsCanCall() {
		var requestCustomizer = new OAuth2ClientCredentialsSyncHttpRequestCustomizer(
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
						authorizedClientService),
				"authserver-client-credentials");

		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.objectMapper(new ObjectMapper())
			.clientBuilder(HttpClient.newBuilder())
			.httpRequestCustomizer(requestCustomizer)
			.build();
		var mcpClientBuilder = McpClient.sync(transport)
			// No authentication context provider required, as this does not rely on
			// thread locals
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			var resp = mcpClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

			assertThat(resp.content()).hasSize(1)
				.first()
				.asInstanceOf(type(McpSchema.TextContent.class))
				.extracting(McpSchema.TextContent::text)
				// the "sub" of the token used in the request is the client id, in
				// client_credentials
				.isEqualTo("Hello default-client");
		}
		catch (Exception e) {
			fail(e);
		}
	}

	@Test
	@DisplayName("Can use hybrid request customizer to use both client_credentials and authorization_code flows")
	void whenHybridAndClientCredentialsCanCall() throws IOException {
		var requestCustomizer = new OAuth2HybridSyncHttpRequestCustomizer(clientManager,
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
						authorizedClientService),
				"authserver", "authserver-client-credentials");

		inMemoryMcpClientRepository.addClient(mcpServerUrl, "test-client-hybrid", requestCustomizer);

		var resp = inMemoryMcpClientRepository.getClientByName("test-client-hybrid")
			.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

		assertThat(resp.content()).hasSize(1)
			.first()
			.asInstanceOf(type(McpSchema.TextContent.class))
			.extracting(McpSchema.TextContent::text)
			// the "sub" of the token used in the request is the client id, in
			// client_credentials
			.isEqualTo("Hello default-client");

		ensureAuthServerLogin();
		var callToolResponse = webClient
			.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=test-client-hybrid&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		// The "sub" of the token is "test-user" in authorization_code flow
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-hybrid, tool: greeter], got response [Hello test-user]");

	}

	@Test
	@DisplayName("When the user is present, they can add a tool and then call it")
	void addToolThenCall() throws IOException {
		ensureAuthServerLogin();

		var uri = UriComponentsBuilder.newInstance()
			.scheme("http")
			.host("127.0.0.1")
			.port(port)
			.path("/tool/add")
			.queryParam("clientName", "greeter")
			.queryParam("url", mcpServerUrl)
			.toUriString();

		var addToolResponse = webClient.getPage(uri);
		assertThat(addToolResponse.getWebResponse().getStatusCode()).isEqualTo(201);

		var callToolResponse = webClient
			.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=greeter&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: greeter, tool: greeter], got response [Hello test-user]");
	}

	private void ensureAuthServerLogin() throws IOException {
		HtmlPage loginPage = this.webClient.getPage(authorizationServerUrl);

		if (loginPage.getWebResponse().getStatusCode() == 404) {
			// Already logged in
			return;
		}
		loginPage.<HtmlInput>querySelector("#username").type("test-user");
		loginPage.<HtmlInput>querySelector("#password").type("test-password");
		loginPage.<HtmlButton>querySelector("button").click();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class,
			StreamableHttpWebFluxTransportAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, McpClientConfiguration.class })
	static class StreamableHttpConfig {

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

	}

}
