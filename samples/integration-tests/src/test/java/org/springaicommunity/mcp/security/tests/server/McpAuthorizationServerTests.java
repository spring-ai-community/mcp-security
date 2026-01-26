package org.springaicommunity.mcp.security.tests.server;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.test.web.servlet.client.assertj.RestTestClientResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("authorization-server")
@AutoConfigureRestTestClient
@AutoConfigureMockMvc
class McpAuthorizationServerTests {

	@LocalServerPort
	int serverPort;

	@Autowired
	RestTestClient client;

	@Autowired
	private MockMvcTester mockMvc;

	@Test
	void oauthServerMetadata() {
		var clientResponse = client.get().uri("/.well-known/oauth-authorization-server").exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatusOk();
		assertThat(response).bodyJson().extractingPath("$.issuer").isEqualTo("http://localhost:" + serverPort);
		assertThat(response).bodyJson()
			.extractingPath("$.registration_endpoint")
			.isEqualTo("http://localhost:" + serverPort + "/oauth2/register");
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
		assertThat(response).hasStatusOk();
		assertThat(response).bodyJson().extractingPath("access_token").isNotNull();
	}

	@Test
	void ignoreConsentWhenNoScopes() {
		var response = mockMvc.get()
			.uri("/oauth2/authorize")
			.queryParam("client_id", "default-client")
			.queryParam("redirect_url", "https://example.com")
			.queryParam("response_type", "code")
			.queryParam("code_challenge", "xxxx")
			.queryParam("code_challenge_method", "S256")
			.with(user("test-user"))
			.exchange();

		assertThat(response).hasStatus(HttpStatus.FOUND)
			.redirectedUrl()
			.startsWith("https://example.com")
			.contains("code=");
	}

	@Test
	void dynamicClientRegistration() {
		var clientResponse = client.post().uri("/oauth2/register").contentType(MediaType.APPLICATION_JSON).body("""
				{
					"redirect_uris": [
						"https://example.com"
					],
					"grant_types": [
						"client_credentials",
						"authorization_code"
					],
					"client_name": "Dynamically Registered Client",
					"token_endpoint_auth_method": "client_secret_basic",
					"scope": "test.read,test.write",
					"resource": "http://localhost:8080/"
				}
				""").exchange();
		var response = RestTestClientResponse.from(clientResponse);

		assertThat(response).hasStatus(HttpStatus.CREATED);
		assertThat(response).bodyJson().extractingPath("client_id").isNotNull();
	}

	@Test
	void useDynamicallyRegisteredClient() {
		var registrationResponse = client.post()
			.uri("/oauth2/register")
			.contentType(MediaType.APPLICATION_JSON)
			.body("""
					{
						"redirect_uris": [
							"https://example.com"
						],
						"grant_types": [
							"client_credentials"
						],
						"client_name": "Client Credentials-based dynamic client",
						"token_endpoint_auth_method": "client_secret_basic",
						"scope": "test.read test.write",
						"resource": "http://localhost:8080/"
					}
					""")
			.exchange();
		var registration = RestTestClientResponse.from(registrationResponse);

		assertThat(registration).hasStatus(HttpStatus.CREATED);
		var mapper = JsonMapper.builder()
			.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false)
			.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
			.build();
		var registredClient = mapper.readValue(registrationResponse.returnResult().getResponseBodyContent(),
				ClientCreationResponse.class);

		var clientResponse = client.post()
			.uri("/oauth2/token")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("grant_type=client_credentials&resource=http://localhost:8080/&scope=test.write")
			.headers(h -> h.setBasicAuth(registredClient.clientId(), registredClient.clientSecret()))
			.exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatusOk();
		assertThat(response).bodyJson().extractingPath("access_token").isNotNull();
	}

	record ClientCreationResponse(String clientId, String clientSecret) {

	}

	@Configuration
	@EnableAutoConfiguration(
			exclude = { SseHttpClientTransportAutoConfiguration.class, SseWebFluxTransportAutoConfiguration.class,
					StreamableHttpWebFluxTransportAutoConfiguration.class, AnthropicChatAutoConfiguration.class })
	static class Config {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.with(McpAuthorizationServerConfigurer.mcpAuthorizationServer(), Customizer.withDefaults())
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.build();
		}

	}

}
