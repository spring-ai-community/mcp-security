package org.springaicommunity.mcp.security.tests.streamable.sync.dcr;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.UUID;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DefaultMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpController;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.ai.mcp.client.common.autoconfigure.McpClientAutoConfiguration;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springaicommunity.mcp.security.client.sync.config.McpClientOAuth2Configurer.mcpClientOAuth2;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
		mcp.server.protocol=STREAMABLE
		mcp.server.validate-audience-claim=true
		""")
class DynamicClientRegistrationTests {

	private static final String PRE_REGISTRATION_ID = "default";

	WebClient webClient = new WebClient();

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@Value("${mcp.server.url}")
	String mcpServerBaseUrl;

	@Value("#{'${mcp.server.url}' + '/mcp'}")
	String mcpServerUrl;

	@LocalServerPort
	int port;

	@Autowired
	private InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@Autowired
	private OAuth2HttpClientTransportCustomizer transportCustomizer;

	@Autowired
	private McpClientRegistrationRepository clientRegistrationRepository;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	@DisplayName("Discover MCP Server authorization needs, automatically register client")
	void fullDynamicClientRegistration() throws IOException {
		var oauth2ClientRegistrationName = UUID.randomUUID().toString();
		assertThat(clientRegistrationRepository.findByRegistrationId(oauth2ClientRegistrationName)).isNull();

		ensureAuthServerLogin();

		var builder = HttpClientStreamableHttpTransport.builder(this.mcpServerBaseUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(new JacksonMcpJsonMapper(new JsonMapper()));
		transportCustomizer.customize(oauth2ClientRegistrationName, builder);
		var transport = builder.build();

		var client = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		inMemoryMcpClientRepository.addClient("test-client-authcode", client);

		var callToolResponse = webClient
			.getPage("http://localhost:" + port + "/tool/call?clientName=test-client-authcode&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-authcode, tool: greeter], got response [Hello test-user]");

		// DCR was performed
		assertThat(clientRegistrationRepository.findByRegistrationId(oauth2ClientRegistrationName)).isNotNull();
	}

	@Test
	@DisplayName("Pre-register client with auth server in configuration")
	void preRegisteredClient() throws IOException {
		var clientRegistrationName = PRE_REGISTRATION_ID;
		var preRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationName);
		assertThat(preRegistration).isNotNull();

		ensureAuthServerLogin();

		var builder = HttpClientStreamableHttpTransport.builder(this.mcpServerBaseUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(new JacksonMcpJsonMapper(new JsonMapper()));
		// we use the same transport name as the existing client registration
		transportCustomizer.customize(clientRegistrationName, builder);
		var transport = builder.build();

		var client = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		inMemoryMcpClientRepository.addClient("test-client-authcode", client);

		var callToolResponse = webClient
			.getPage("http://localhost:" + port + "/tool/call?clientName=test-client-authcode&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-authcode, tool: greeter], got response [Hello test-user]");

		// No DCR: registration existed already
		assertThat(clientRegistrationRepository.findByRegistrationId(clientRegistrationName)).isNotNull();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(
			exclude = { OAuth2AuthorizationServerJwtAutoConfiguration.class, McpClientAutoConfiguration.class,
					SseHttpClientTransportAutoConfiguration.class, SseWebFluxTransportAutoConfiguration.class,
					StreamableHttpWebFluxTransportAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, InMemoryMcpClientRepository.class,
			McpController.class })
	static class StreamableHttpConfig {

		@Bean
		McpClientCustomizer<McpClient.SyncSpec> syncClientCustomizer() {
			return (name, syncSpec) -> syncSpec
				.transportContextProvider(new AuthenticationMcpTransportContextProvider());
		}

		@Bean
		OAuth2HttpClientTransportCustomizer clientTransportCustomizer(
				OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
				ClientRegistrationRepository clientRegistrationRepository,
				McpOAuth2ClientManager mcpOAuth2ClientManager) {
			return new OAuth2HttpClientTransportCustomizer(oAuth2AuthorizedClientManager, clientRegistrationRepository,
					mcpOAuth2ClientManager);
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http,
				@Value("${mcp.server.url}") String mcpServerBaseUrl) {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.with(mcpClientOAuth2(),
						oauth2 -> oauth2.registerMcpOAuth2Client(PRE_REGISTRATION_ID, mcpServerBaseUrl + "/mcp"))
				.build();
		}

		@Bean
		McpOAuth2ClientManager mcpOAuth2ClientManager(McpClientRegistrationRepository mcpClientRegistrationRepository) {
			return new DefaultMcpOAuth2ClientManager(mcpClientRegistrationRepository,
					new DynamicClientRegistrationService(), new McpMetadataDiscoveryService());
		}

		@Bean
		McpClientRegistrationRepository mcpClientRegistrationRepository() {
			return new InMemoryMcpClientRegistrationRepository();
		}

		@Bean
		OAuth2AuthorizedClientManager authorizedClientManager(
				ClientRegistrationRepository mcpClientRegistrationRepository,
				OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
			return new DefaultOAuth2AuthorizedClientManager(mcpClientRegistrationRepository,
					oAuth2AuthorizedClientRepository);
		}

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

}
