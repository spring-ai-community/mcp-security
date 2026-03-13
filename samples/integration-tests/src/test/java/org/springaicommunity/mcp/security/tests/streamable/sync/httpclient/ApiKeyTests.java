package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.atomic.AtomicReference;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.McpHttpClientTransportAuthorizationException;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import org.assertj.core.api.ThrowableAssert;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerApiKeyConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.ApiKeysAbstractTests;
import tools.jackson.databind.json.JsonMapper;

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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpApiKeyServer
		mcp.server.protocol=STREAMABLE
		""")
public class ApiKeyTests extends ApiKeysAbstractTests {

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new JsonMapper());

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	@Override
	protected McpClientTransport buildUnauthenticatedTransport() {
		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.httpRequestCustomizer(
					(builder, method, endpoint, body, context) -> builder.header("X-API-key", "api01.wrongkey"))
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

	@Override
	protected McpClientTransport buildAuthenticatedTransport(AtomicReference<String> currentApiKey) {
		return HttpClientStreamableHttpTransport.builder(this.mcpServerUrl)
			.jsonMapper(jsonMapper)
			.clientBuilder(HttpClient.newBuilder())
			.httpRequestCustomizer(
					(builder, method, endpoint, body, context) -> builder.header("X-API-key", currentApiKey.get()))
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
