package org.springaicommunity.mcp.security.tests.server;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;

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
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.test.web.servlet.client.assertj.RestTestClientResponse;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("authorization-server")
@AutoConfigureRestTestClient
class McpAuthorizationServerTests {

	@LocalServerPort
	int serverPort;

	@Autowired
	RestTestClient client;

	@Test
	void oauthServerMetadata() {
		var clientResponse = client.get().uri("/.well-known/oauth-authorization-server").exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatusOk();
		assertThat(response).bodyJson().extractingPath("$.issuer").isEqualTo("http://localhost:" + serverPort);
	}

	@Test
	void clientCredentialsToken() {
		var clientResponse = client.post()
			.uri("/oauth2/token")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("grant_type=client_credentials&resource=https://example.com")
			.headers(h -> h.setBasicAuth("default-client", "default-secret"))
			.exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).bodyJson().extractingPath("access_token").isNotNull();
	}

	@Configuration
	@EnableAutoConfiguration(
			exclude = { SseHttpClientTransportAutoConfiguration.class, SseWebFluxTransportAutoConfiguration.class,
					StreamableHttpWebFluxTransportAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	static class Config {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), (cfg) -> {
				})
				.build();
		}

	}

}
