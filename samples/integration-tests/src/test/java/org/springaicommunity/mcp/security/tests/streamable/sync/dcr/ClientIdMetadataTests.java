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
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2CimdHttpClientTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.DefaultMcpOAuth2CimdClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.McpOAuth2CimdClientManager;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpController;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.ai.mcp.client.common.autoconfigure.McpClientAutoConfiguration;
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
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata.ClientIdUrlValidator;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
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
class ClientIdMetadataTests {

	WebClient webClient = new WebClient();

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@Value("${mcp.server.url}")
	String mcpServerBaseUrl;

	@LocalServerPort
	int port;

	@Autowired
	private InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@Autowired
	private McpClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	private OAuth2CimdHttpClientTransportCustomizer transportCustomizer;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	@DisplayName("Discover MCP Server authorization needs, request token with CIMD url, get resource")
	void fullCimdRegistration() throws IOException {
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
		assertThat(clientRegistrationRepository.findByRegistrationId(oauth2ClientRegistrationName)).isNotNull()
			.extracting(ClientRegistration::getClientId)
			.isEqualTo("http://localhost:%s/%s/client-id-metadata.json".formatted(port, oauth2ClientRegistrationName));
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(
			exclude = { OAuth2AuthorizationServerJwtAutoConfiguration.class, McpClientAutoConfiguration.class,
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
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.with(mcpClientOAuth2(), mcp -> mcp.cimd(true))
				.build();
		}

		@Bean
		McpOAuth2CimdClientManager mcpOAuth2CimdClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository) {
			var validator = new DefaultUrlValidator(true);
			return new DefaultMcpOAuth2CimdClientManager(new McpMetadataDiscoveryService(validator),
					mcpClientRegistrationRepository, new DefaultUrlValidator(true));
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

		@Bean
		OAuth2CimdHttpClientTransportCustomizer transportCustomizer(
				OAuth2AuthorizedClientManager authorizedClientManager,
				McpClientRegistrationRepository mcpClientRegistrationRepository,
				McpOAuth2CimdClientManager mcpOAuth2CimdClientManager) {
			return new OAuth2CimdHttpClientTransportCustomizer(authorizedClientManager, mcpClientRegistrationRepository,
					mcpOAuth2CimdClientManager);
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
