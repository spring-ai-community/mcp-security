package org.springaicommunity.mcp.security.tests.streamable.sync.webclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.transport.WebClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import org.junit.jupiter.api.Nested;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2AuthorizationCodeExchangeFilterFunction;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2ClientCredentialsExchangeFilterFunction;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2HybridExchangeFilterFunction;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.StreamableHttpAbstractTests;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.StreamableHttpHttpClientTransportAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Note: Here specify the main configuration class so that nested tests know which
 * configuration to pick up. Otherwise, configuration scanning does not find the nested
 * config class in {@link Nested} tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		classes = StreamableHttpWebClientTests.StreamableHttpConfig.class,
		properties = "mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer")
@ActiveProfiles("sync")
class StreamableHttpWebClientTests extends StreamableHttpAbstractTests {

	@Autowired
	org.springframework.web.reactive.function.client.WebClient.Builder webClientBuilder;

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new ObjectMapper());

	@Override
	public McpClientTransport buildNoSecurityTransport() {
		var clientBuilder = webClientBuilder.clone().baseUrl(mcpServerUrl);
		return WebClientStreamableHttpTransport.builder(clientBuilder).jsonMapper(jsonMapper).build();
	}

	@Override
	public McpClientTransport buildAuthorizationCodeTransport() {
		var clientBuilder = webClientBuilder.clone()
			.baseUrl(mcpServerUrl)
			.filter(new McpOAuth2AuthorizationCodeExchangeFilterFunction(clientManager, "authserver"));

		return WebClientStreamableHttpTransport.builder(clientBuilder).jsonMapper(jsonMapper).build();
	}

	@Override
	public McpClientTransport buildHybridTransport() {
		var clientBuilder = webClientBuilder.clone()
			.baseUrl(mcpServerUrl)
			.filter(new McpOAuth2HybridExchangeFilterFunction(clientManager,
					new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
							authorizedClientService),
					"authserver", "authserver-client-credentials"));

		return WebClientStreamableHttpTransport.builder(clientBuilder).jsonMapper(jsonMapper).build();
	}

	@Override
	public McpClientTransport buildClientCredentialsTransport() {
		var clientBuilder = webClientBuilder.clone()
			.baseUrl(mcpServerUrl)
			.filter(new McpOAuth2ClientCredentialsExchangeFilterFunction(clientManager, clientRegistrationRepository,
					"authserver-client-credentials"));

		return WebClientStreamableHttpTransport.builder(clientBuilder).jsonMapper(jsonMapper).build();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class,
			StreamableHttpHttpClientTransportAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, McpClientConfiguration.class })
	static class StreamableHttpConfig {

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

	}

}
