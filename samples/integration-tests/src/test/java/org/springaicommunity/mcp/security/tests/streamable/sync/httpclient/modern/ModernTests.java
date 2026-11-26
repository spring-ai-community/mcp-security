package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient.modern;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

import io.modelcontextprotocol.modern.McpSchema;
import io.modelcontextprotocol.modern.client.McpClient;
import io.modelcontextprotocol.modern.client.McpSyncClient;
import io.modelcontextprotocol.modern.client.transport.HttpClientMcpTransport;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestCustomizer;
import io.modelcontextprotocol.modern.client.transport.McpHttpStatusException;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern.OAuth2AuthorizationCodeRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern.OAuth2ClientCredentialsRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern.OAuth2HttpClientMcpTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.tests.InMemoryModernMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;

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
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.json.JsonContent;
import org.springframework.test.json.JsonContentAssert;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Integration tests for the 2026-07-28 ("modern") MCP protocol: a modern client, from the
 * MCP Java SDK, calls a modern MCP server secured with OAuth2.
 * <p>
 * Modern clients that need a user call tools through
 * {@link org.springaicommunity.mcp.security.tests.ModernMcpController}, on
 * {@code /modern/tool/call}, so that the authorization code flow runs in a servlet
 * request.
 */
@ActiveProfiles("sync")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
		mcp.server.protocol=MODERN
		""")
class ModernTests {

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@Value("${mcp.server.url}")
	String mcpServerBaseUrl;

	@LocalServerPort
	int port;

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	McpClientRegistrationRepository mcpClientRegistrationRepository;

	@Autowired
	OAuth2AuthorizedClientService authorizedClientService;

	@Autowired
	OAuth2AuthorizedClientManager authorizedClientManager;

	@Autowired
	McpOAuth2ClientManager mcpOAuth2ClientManager;

	@Autowired
	InMemoryModernMcpClientRepository modernClientRepository;

	WebClient webClient = new WebClient();

	String mcpServerUrl;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.mcpServerUrl = this.mcpServerBaseUrl + "/mcp";
	}

	@Test
	@DisplayName("Can fetch resource metadata")
	void resourceMetadata() {
		var restClient = RestClient.builder().defaultStatusHandler(status -> true, (request, response) -> {
		}).build();
		var response = restClient.post().uri(this.mcpServerUrl).retrieve().toBodilessEntity();

		assertThat(response.getStatusCode().value()).isEqualTo(401);
		var wwwAuthenticate = response.getHeaders().getFirst("www-authenticate");
		var pattern = Pattern.compile("^Bearer resource_metadata=(?<metadataUrl>.*)$");
		var matcher = pattern.matcher(wwwAuthenticate);
		assertThat(matcher.find()).isTrue();
		var metadataUrl = matcher.group("metadataUrl");
		assertThat(metadataUrl).contains(".well-known/oauth-protected-resource");

		var protectedResourceMetadata = restClient.get().uri(metadataUrl).retrieve().body(String.class);
		new JsonContentAssert(new JsonContent(protectedResourceMetadata))
			.hasPathSatisfying("$.resource", r -> assertThat(r).isEqualTo(this.mcpServerUrl))
			.hasPathSatisfying("$.authorization_servers[0]",
					as -> assertThat(as).isEqualTo(this.authorizationServerUrl));
	}

	@Test
	@DisplayName("Without oauth2 support, cannot call tools")
	void noSecurity() {
		var client = buildClient(HttpClientMcpTransport.builder(this.mcpServerUrl));

		assertThatExceptionOfType(McpHttpStatusException.class).isThrownBy(() -> client.tool("greeter").call())
			.extracting(McpHttpStatusException::statusCode)
			.isEqualTo(401);
	}

	@Test
	@DisplayName("With authorization_code, when no user is present, cannot call tools")
	void authorizationCodeNoUser() throws IOException {
		ensureAuthServerLogin();
		var customizer = new OAuth2AuthorizationCodeRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, "authserver");
		var client = buildClient(HttpClientMcpTransport.builder(this.mcpServerUrl)
			.requestCustomizer(McpHttpRequestCustomizer.fromSync(customizer)));

		assertThatExceptionOfType(McpHttpStatusException.class).isThrownBy(() -> client.tool("greeter").call())
			.extracting(McpHttpStatusException::statusCode)
			.isEqualTo(401);
	}

	@Test
	@DisplayName("With client_credentials, when no user is present, can call tools")
	void clientCredentials() {
		var customizer = new OAuth2ClientCredentialsRequestCustomizer(
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(this.clientRegistrationRepository,
						this.authorizedClientService),
				"authserver-client-credentials");
		var client = buildClient(HttpClientMcpTransport.builder(this.mcpServerUrl)
			.requestCustomizer(McpHttpRequestCustomizer.fromSync(customizer)));

		var result = client.tool("greeter").call();

		assertThat(result.content()).hasSize(1)
			.first()
			.isInstanceOfSatisfying(McpSchema.TextContent.class,
					// the "sub" of the token is the client id, in client_credentials
					content -> assertThat(content.text()).isEqualTo("Hello default-client"));
	}

	@Test
	@DisplayName("With authorization_code, when the user is present, can call tools")
	void authorizationCode() throws IOException {
		ensureAuthServerLogin();
		var customizer = new OAuth2AuthorizationCodeRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, "authserver");
		var client = buildClient(HttpClientMcpTransport.builder(this.mcpServerUrl)
			.requestCustomizer(McpHttpRequestCustomizer.fromSync(customizer)));
		this.modernClientRepository.addClient("modern-authcode", client);

		var response = this.webClient
			.getPage("http://127.0.0.1:" + this.port + "/modern/tool/call?clientName=modern-authcode&toolName=greeter");

		assertThat(response.getWebResponse().getContentAsString())
			.isEqualTo("Called [client: modern-authcode, tool: greeter], got response [Hello test-user]");
	}

	@Test
	@DisplayName("Discover MCP Server authorization needs, register client with DCR, call tools")
	void dynamicClientRegistration() throws IOException {
		var registrationId = UUID.randomUUID().toString();
		assertThat(this.mcpClientRegistrationRepository.findByRegistrationId(registrationId)).isNull();
		ensureAuthServerLogin();
		var transportCustomizer = new OAuth2HttpClientMcpTransportCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, this.mcpOAuth2ClientManager);
		var transport = HttpClientMcpTransport.builder(this.mcpServerUrl);
		transportCustomizer.customize(registrationId, transport);
		this.modernClientRepository.addClient("modern-dcr", buildClient(transport));

		var response = this.webClient
			.getPage("http://localhost:" + this.port + "/modern/tool/call?clientName=modern-dcr&toolName=greeter");

		assertThat(response.getWebResponse().getContentAsString())
			.isEqualTo("Called [client: modern-dcr, tool: greeter], got response [Hello test-user]");
		// DCR was performed
		assertThat(this.mcpClientRegistrationRepository.findByRegistrationId(registrationId)).isNotNull();
	}

	private static McpSyncClient buildClient(HttpClientMcpTransport.Builder transport) {
		return McpClient.sync(transport.build())
			.clientInfo(McpSchema.Implementation.builder("modern-test-client", "1.0.0").build())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
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

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, McpClientConfiguration.class })
	static class ModernConfig {

	}

}
