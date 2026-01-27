package org.springaicommunity.mcp.security.tests.server;

import java.util.List;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Disabled;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.test.web.servlet.client.assertj.RestTestClientResponse;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		spring.ai.mcp.server.protocol=STATELESS
		spring.ai.mcp.client.type=SYNC
		server.servlet.context-path=/ctx
		logging.level.org.springframework.security=TRACE
		""")
@AutoConfigureRestTestClient
class McpServerTests {

	@LocalServerPort
	int serverPort;

	@Autowired
	RestTestClient client;

	@Autowired
	private JwtEncoder jwtEncoder;

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
				    "https://example.com"
				  ],
				  "resource_name": "Spring MCP Resource Server",
				  "bearer_methods_supported": [
				    "header"
				  ]
				}
				""").extractingPath("$.resource").isEqualTo("http://localhost:%s/ctx/mcp".formatted(serverPort));
	}

	@Test
	void requestWithToken() {
		var jwt = jwt();

		var clientResponse = client.get().uri("/").headers(h -> h.setBearerAuth(jwt.getTokenValue())).exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatus(HttpStatus.NOT_FOUND);
	}

	@Test
	void requestWithTokenIncludeScopeScope() {
		var jwt = jwt("test.read", "test.write");

		var clientResponse = client.get()
			.uri("/with-write-scope")
			.headers(h -> h.setBearerAuth(jwt.getTokenValue()))
			.exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatus(HttpStatus.NOT_FOUND);
	}

	@Test
	@Disabled("Not implemented. See https://github.com/spring-ai-community/mcp-security/issues/18")
	void requestWithTokenMissingScope() {
		var jwt = jwt("test.read");

		var clientResponse = client.get()
			.uri("/with-write-scope")
			.headers(h -> h.setBearerAuth(jwt.getTokenValue()))
			.exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatus(HttpStatus.FORBIDDEN)
			.headers()
			.hasHeaderSatisfying(HttpHeaders.WWW_AUTHENTICATE,
					values -> assertThat(values).hasSize(1)
						.first()
						.asString()
						.contains("error=\"insufficient_scope\"")
						.contains("scope=\"test.write\""));
	}

	private Jwt jwt(String... scopes) {
		var header = JwsHeader.with(MacAlgorithm.HS512).build();
		var claimsBuilder = JwtClaimsSet.builder().audience(List.of("http://localhost:%s/mcp".formatted(serverPort)));
		if (scopes.length > 0) {
			claimsBuilder.claim("scope", String.join(" ", scopes));
		}
		var claims = claimsBuilder.build();
		return jwtEncoder.encode(JwtEncoderParameters.from(header, claims));
	}

	/**
	 * This test app uses symmetric key JWT signing. With this, we don't need RSA keys,
	 * and we can sign easily sign tokens locally without having to relying on an
	 * auth-server.
	 */
	@Configuration
	@EnableAutoConfiguration(
			exclude = { SseHttpClientTransportAutoConfiguration.class, SseWebFluxTransportAutoConfiguration.class,
					StreamableHttpWebFluxTransportAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	static class Config {

		private static final ImmutableSecret<SecurityContext> SECRET = new ImmutableSecret<>(
				"0558BC36-378D-4809-A551-E61F3B8894B9-8ECA8B16-D07E-4856-9564-50637494E51A".getBytes());

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) {
			return http.authorizeHttpRequests(authz -> {
				authz.requestMatchers("/with-write-scope").hasAuthority("SCOPE_test.write");
				authz.anyRequest().authenticated();
			})
				.with(McpServerOAuth2Configurer.mcpServerOAuth2()
					.authorizationServer("https://example.com")
					.jwtDecoder(jwtDecoder))
				.build();
		}

		@Bean
		JwtEncoder jwtEncoder() {
			return new NimbusJwtEncoder(SECRET);
		}

		@Bean
		public JwtDecoder jwtDecoder() {
			return NimbusJwtDecoder.withSecretKey(SECRET.getSecretKey()).macAlgorithm(MacAlgorithm.HS512).build();
		}

	}

}
