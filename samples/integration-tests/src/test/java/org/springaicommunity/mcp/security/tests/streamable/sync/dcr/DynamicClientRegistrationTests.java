package org.springaicommunity.mcp.security.tests.streamable.sync.dcr;

import java.io.IOException;
import java.net.http.HttpClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpController;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;

import org.springframework.ai.mcp.client.common.autoconfigure.McpClientAutoConfiguration;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
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
import org.springframework.security.config.Customizer;
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

	WebClient webClient = new WebClient();

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	@LocalServerPort
	int port;

	@Autowired
	private OAuth2AuthorizedClientManager clientManager;

	@Autowired
	private InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	void canCallTool() throws IOException {
		ensureAuthServerLogin();

		var requestCustomizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(this.clientManager, "default");

		var transport = HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper()))
			.httpRequestCustomizer(requestCustomizer)
			.build();

		var client = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		inMemoryMcpClientRepository.addClient("test-client-authcode", client);

		var callToolResponse = webClient
			.getPage("http://localhost:" + port + "/tool/call?clientName=test-client-authcode&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-authcode, tool: greeter], got response [Hello test-user]");
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
		McpSyncClientCustomizer syncClientCustomizer() {
			return (name, syncSpec) -> syncSpec
				.transportContextProvider(new AuthenticationMcpTransportContextProvider());
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http, @Value("${mcp.server.url}") String mcpServerUrl) {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.with(mcpClientOAuth2(), oauth2 -> oauth2.registerMcpOAuth2Client("default", mcpServerUrl + "/mcp"))
				.build();
		}

		@Bean
		McpClientRegistrationRepository mcpClientRegistrationRepository() {
			return new InMemoryMcpClientRegistrationRepository(new DynamicClientRegistrationService(),
					new McpMetadataDiscoveryService());
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
