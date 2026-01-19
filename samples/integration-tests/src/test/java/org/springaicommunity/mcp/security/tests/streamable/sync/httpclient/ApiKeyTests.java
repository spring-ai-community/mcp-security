package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerApiKeyConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.ApiKeysAbstractTests;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpApiKeyServer
		mcp.server.protocol=STREAMABLE
		""")
public class ApiKeyTests extends ApiKeysAbstractTests {

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new ObjectMapper());

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	@Override
	protected McpClientTransport buildUnauthenticatedTransport() {
		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.build();
	}

	@Override
	protected McpClientTransport buildAuthenticatedTransport() {
		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.requestBuilder(HttpRequest.newBuilder().header("X-API-key", "api01.mycustomapikey"))
			.build();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpWebFluxTransportAutoConfiguration.class,
			AnthropicChatAutoConfiguration.class })
	@Import({ McpServerApiKeyConfiguration.class })
	static class ApiKeyConfig {

	}

}
