package org.springaicommunity.mcp.security.tests.streamable.sync.webclient;

import java.net.http.HttpResponse;
import java.util.concurrent.atomic.AtomicReference;

import io.modelcontextprotocol.client.transport.McpHttpClientTransportAuthorizationException;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpTransportException;
import org.assertj.core.api.ThrowableAssert;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerApiKeyConfiguration;
import org.springaicommunity.mcp.security.tests.common.tests.ApiKeysAbstractTests;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.StreamableHttpHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.transport.WebClientStreamableHttpTransport;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpApiKeyServer
		mcp.server.protocol=STREAMABLE
		""")
public class WebClientApiKeyTests extends ApiKeysAbstractTests {

	private final JacksonMcpJsonMapper jsonMapper = new JacksonMcpJsonMapper(new JsonMapper());

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

	@Override
	protected McpClientTransport buildAuthenticatedTransport(AtomicReference<String> currentApiKey) {
		return WebClientStreamableHttpTransport
			.builder(WebClient.builder().baseUrl(this.mcpServerUrl).filter((request, next) -> {
				var requestWithApiKey = ClientRequest.from(request).header("X-API-Key", currentApiKey.get()).build();
				return next.exchange(requestWithApiKey);
			}))
			.jsonMapper(jsonMapper)
			.build();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpHttpClientTransportAutoConfiguration.class,
			AnthropicChatAutoConfiguration.class })
	@Import({ McpServerApiKeyConfiguration.class })
	static class ApiKeyConfig {

	}

}
