package org.springaicommunity.mcp.security.tests.streamable.sync.webclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.transport.WebClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerApiKeyConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.ApiKeysAbstractTests;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.StreamableHttpHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpApiKeyServer
		mcp.server.protocol=STREAMABLE
		""")
public class WebClientApiKeyTests extends ApiKeysAbstractTests {

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new ObjectMapper());

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	@Override
	protected McpClientTransport buildUnauthenticatedTransport() {
		return WebClientStreamableHttpTransport
			.builder(WebClient.builder().baseUrl(this.mcpServerUrl).defaultHeader("X-API-Key", "api01.wrongkey"))
			.jsonMapper(jsonMapper)
			.build();
	}

	@Override
	protected McpClientTransport buildAuthenticatedTransport() {
		return WebClientStreamableHttpTransport
			.builder(WebClient.builder().baseUrl(this.mcpServerUrl).defaultHeader("X-API-Key", "api01.mycustomapikey"))
			.jsonMapper(jsonMapper)
			.build();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpHttpClientTransportAutoConfiguration.class })
	@Import({ McpServerApiKeyConfiguration.class })
	static class ApiKeyConfig {

	}

}
