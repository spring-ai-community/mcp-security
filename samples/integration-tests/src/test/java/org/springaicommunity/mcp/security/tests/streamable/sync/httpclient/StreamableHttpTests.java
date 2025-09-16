package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import java.net.http.HttpClient;
import org.junit.jupiter.api.Nested;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2ClientCredentialsSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HybridSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.StreamableHttpAbstractTests;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
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
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Note: Here specify the main configuration class so that nested tests know which
 * configuration to pick up. Otherwise, configuration scanning does not find the nested
 * config class in {@link Nested} tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
		mcp.server.protocol=STREAMABLE
		""")
class StreamableHttpTests extends StreamableHttpAbstractTests {

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new ObjectMapper());

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpWebFluxTransportAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, McpClientConfiguration.class })
	static class StreamableHttpConfig {

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

	}

	@Override
	public McpClientTransport buildNoSecurityTransport() {
		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.build();
	}

	@Override
	public HttpClientStreamableHttpTransport buildAuthorizationCodeTransport() {
		var requestCustomizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(this.clientManager, "authserver");

		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(jsonMapper)
			.httpRequestCustomizer(requestCustomizer)
			.build();
	}

	@Override
	public HttpClientStreamableHttpTransport buildHybridTransport() {
		var requestCustomizer = new OAuth2HybridSyncHttpRequestCustomizer(clientManager,
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
						authorizedClientService),
				"authserver", "authserver-client-credentials");

		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.clientBuilder(HttpClient.newBuilder())
			.jsonMapper(jsonMapper)
			.httpRequestCustomizer(requestCustomizer)
			.build();
		return transport;
	}

	@Override
	public HttpClientStreamableHttpTransport buildClientCredentialsTransport() {
		var requestCustomizer = new OAuth2ClientCredentialsSyncHttpRequestCustomizer(
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
						authorizedClientService),
				"authserver-client-credentials");

		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.httpRequestCustomizer(requestCustomizer)
			.build();
		return transport;
	}

}
