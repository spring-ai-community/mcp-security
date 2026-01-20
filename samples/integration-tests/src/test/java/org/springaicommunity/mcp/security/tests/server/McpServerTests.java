package org.springaicommunity.mcp.security.tests.server;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.test.web.servlet.client.assertj.RestTestClientResponse;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		spring.ai.mcp.server.protocol=STATELESS
		spring.ai.mcp.client.type=SYNC
		server.servlet.context-path=/ctx
		""")
@AutoConfigureRestTestClient
class McpServerTests {

	@LocalServerPort
	int serverPort;

	@Autowired
	RestTestClient client;

	@Test
	void wwwAuthenticate() {
		var clientResponse = client.post().uri("/mcp").exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatus(HttpStatus.UNAUTHORIZED);
		assertThat(response).headers()
			.hasSingleValue("WWW-Authenticate",
					"Bearer resource_metadata=http://localhost:%s/ctx/.well-known/oauth-protected-resource/mcp"
						.formatted(serverPort));
	}

	@Test
	void metadataEndpoint() {
		var clientResponse = client.get().uri("/.well-known/oauth-protected-resource/mcp").exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatus2xxSuccessful();
		assertThat(response).bodyJson().isLenientlyEqualTo("""
				{
				  "authorization_servers": [
				    "https://accounts.google.com"
				  ],
				  "resource_name": "Spring MCP Resource Server",
				  "bearer_methods_supported": [
				    "header"
				  ]
				}
				""").extractingPath("$.resource").isEqualTo("http://localhost:%s/ctx/mcp".formatted(serverPort));
	}

	@Configuration
	@EnableAutoConfiguration(
			exclude = { SseHttpClientTransportAutoConfiguration.class, SseWebFluxTransportAutoConfiguration.class,
					StreamableHttpWebFluxTransportAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	static class Config {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(McpServerOAuth2Configurer.mcpServerOAuth2()
					// We need to specify a real authorization server so the app can boot.
					// Accounts.oogle.com is a public auth server so we use that.
					.authorizationServer("https://accounts.google.com"))
				.build();
		}

	}

}
