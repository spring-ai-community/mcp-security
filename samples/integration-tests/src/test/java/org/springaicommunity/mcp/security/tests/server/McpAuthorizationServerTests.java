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
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

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

	private final JsonMapper mapper = JsonMapper.builder().build();

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

		var payload = extractAccessTokenClaims(response);
		assertThat(payload).containsEntry("aud", "https://example.com");
	}

	@Test
	void clientCredentialsTokenNoResource() {
		var clientResponse = client.post()
			.uri("/oauth2/token")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("grant_type=client_credentials")
			.headers(h -> h.setBasicAuth("default-client", "default-secret"))
			.exchange();

		var response = RestTestClientResponse.from(clientResponse);
		assertThat(response).hasStatusOk();
		assertThat(response).bodyJson().extractingPath("access_token").isNotNull();
		var payload = extractAccessTokenClaims(response);
		assertThat(payload).containsEntry("aud", "default-client");
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

	@Test
	void useDynamicallyRegisteredClientWithRefreshToken() throws NoSuchAlgorithmException {
		var registrationResponse = client.post()
				.uri("/oauth2/register")
				.contentType(MediaType.APPLICATION_JSON)
				.body("""
					{
						"redirect_uris": [
							"https://example.com"
						],
						"grant_types": [
							"client_credentials",
							"authorization_code",
							"refresh_token"
						],
						"client_name": "auth-code-test-client",
						"token_endpoint_auth_method": "client_secret_post",
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
		var registeredClient = mapper.readValue(registrationResponse.returnResult().getResponseBodyContent(),
				ClientCreationResponse.class);

		// prepare the oauth2 authorize call
		var code_verifier = "spring-ai-community";
		var code_challenge = generateCodeChallenge(code_verifier);
		var response = mockMvc.get()
				.uri("/oauth2/authorize")
				.queryParam("client_id", registeredClient.clientId())
				.queryParam("redirect_url", "https://example.com")
				.queryParam("response_type", "code")
				.queryParam("code_challenge", code_challenge)
				.queryParam("code_challenge_method", "S256")
				.with(user("test-user"))
				.exchange();

		// validate the presence of the authorization code
		assertThat(response).hasStatus(HttpStatus.FOUND)
				.redirectedUrl()
				.startsWith("https://example.com")
				.contains("code=");

		// extract authorization code
		String code = UriComponentsBuilder.fromUriString(Objects.requireNonNull(response.getResponse().getRedirectedUrl()))
				.build()
				.getQueryParams()
				.getFirst("code");

		assertThat(code).isNotNull();

		// the Oauth2 Token endpoint call based on the authorization_code grant type
		var clientResponse = client.post()
				.uri("/oauth2/token")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("client_id=" + registeredClient.clientId() +
						"&client_secret=" + registeredClient.clientSecret() +
						"&grant_type=authorization_code" +
						"&scope=test.write" +
						"&code_verifier=" +code_verifier +
						"&code=" + code)
				.exchange();

		var tokenEndpointRestTestClientResponse = RestTestClientResponse.from(clientResponse);

		assertThat(tokenEndpointRestTestClientResponse).hasStatusOk();
		assertThat(tokenEndpointRestTestClientResponse).bodyJson().extractingPath("access_token").isNotNull();
		// refresh_token must be present
		assertThat(tokenEndpointRestTestClientResponse).bodyJson().extractingPath("refresh_token").isNotNull();

		var tokenResponse = mapper.readValue(tokenEndpointRestTestClientResponse.getExchangeResult().getResponseBodyContent(), Map.class);;
		var refreshToken = tokenResponse.get("refresh_token").toString();

		var accessTokenClaimsMap = extractAccessTokenClaims(tokenEndpointRestTestClientResponse);
		assertThat(accessTokenClaimsMap).containsEntry("aud", registeredClient.clientId());

		// the Token endpoint call based on the refresh_token grant type
		var refreshTokenResponse = client.post()
				.uri("/oauth2/token")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("client_id="+registeredClient.clientId()+"&client_secret="+registeredClient.clientSecret()+"&grant_type=refresh_token&refresh_token="+refreshToken)
				.exchange();

		var refreshTokenRestTestClientResponse = RestTestClientResponse.from(refreshTokenResponse);
		assertThat(refreshTokenRestTestClientResponse).hasStatusOk();
		// Voilà access_token refreshed
		assertThat(refreshTokenRestTestClientResponse).bodyJson().extractingPath("access_token").isNotNull();
		assertThat(refreshTokenRestTestClientResponse).bodyJson().extractingPath("refresh_token").isNotNull();

		var refreshedAccessTokenClaimsMap = extractAccessTokenClaims(refreshTokenRestTestClientResponse);
		assertThat(refreshedAccessTokenClaimsMap).containsEntry("aud", registeredClient.clientId());
	}

	@Test
	void useDefaultClientWithRefreshToken() throws NoSuchAlgorithmException {
		// prepare the oauth2 authorize call
		var code_verifier = "spring-ai-community";
		var code_challenge = generateCodeChallenge(code_verifier);
		var response = mockMvc.get()
				.uri("/oauth2/authorize")
				.queryParam("client_id", "default-client")
				.queryParam("redirect_url", "https://example.com")
				.queryParam("response_type", "code")
				.queryParam("code_challenge", code_challenge)
				.queryParam("code_challenge_method", "S256")
				.queryParam("resource", "https://example.com")
				.with(user("test-user"))
				.headers(h -> h.setBasicAuth("default-client", "default-secret"))
				.exchange();

		// validate the presence of the authorization code
		assertThat(response).hasStatus(HttpStatus.FOUND)
				.redirectedUrl()
				.startsWith("https://example.com")
				.contains("code=");

		// extract authorization code
		String code = UriComponentsBuilder.fromUriString(Objects.requireNonNull(response.getResponse().getRedirectedUrl()))
				.build()
				.getQueryParams()
				.getFirst("code");

		assertThat(code).isNotNull();

		// the Oauth2 Token endpoint call based on the authorization_code grant type
		var clientResponse = client.post()
				.uri("/oauth2/token")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("grant_type=authorization_code" +
						"&scope=test.write" +
						"&resource=https://example.com" +
						"&code_verifier=" +code_verifier +
						"&code=" + code)
				.headers(h -> h.setBasicAuth("default-client", "default-secret"))
				.exchange();

		var tokenEndpointRestTestClientResponse = RestTestClientResponse.from(clientResponse);

		assertThat(tokenEndpointRestTestClientResponse).hasStatusOk();
		assertThat(tokenEndpointRestTestClientResponse).bodyJson().extractingPath("access_token").isNotNull();
		// refresh_token must be present
		assertThat(tokenEndpointRestTestClientResponse).bodyJson().extractingPath("refresh_token").isNotNull();

		var tokenResponse = mapper.readValue(tokenEndpointRestTestClientResponse.getExchangeResult().getResponseBodyContent(), Map.class);;
		var refreshToken = tokenResponse.get("refresh_token").toString();

		var accessTokenClaimsMap = extractAccessTokenClaims(tokenEndpointRestTestClientResponse);
		assertThat(accessTokenClaimsMap).containsEntry("aud", "https://example.com");

		// the Token endpoint call based on the refresh_token grant type
		var refreshTokenResponse = client.post()
				.uri("/oauth2/token")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("&grant_type=refresh_token&resource=https://example.com&refresh_token="+refreshToken)
				.headers(h -> h.setBasicAuth("default-client", "default-secret"))
				.exchange();

		var refreshTokenRestTestClientResponse = RestTestClientResponse.from(refreshTokenResponse);
		assertThat(refreshTokenRestTestClientResponse).hasStatusOk();
		// Voilà access_token refreshed
		assertThat(refreshTokenRestTestClientResponse).bodyJson().extractingPath("access_token").isNotNull();
		assertThat(refreshTokenRestTestClientResponse).bodyJson().extractingPath("refresh_token").isNotNull();

		var refreshedAccessTokenClaimsMap = extractAccessTokenClaims(refreshTokenRestTestClientResponse);
		assertThat(refreshedAccessTokenClaimsMap).containsEntry("aud", "https://example.com");
	}

	record ClientCreationResponse(String clientId, String clientSecret) {

	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> extractAccessTokenClaims(RestTestClientResponse response) {
		var tokenResponse = mapper.readValue(response.getExchangeResult().getResponseBodyContent(), Map.class);
		var accessToken = tokenResponse.get("access_token").toString();
		var jwtPayload = accessToken.split("\\.")[1];
		var decodedPayload = Base64.getUrlDecoder().decode(jwtPayload);
		return mapper.readValue(decodedPayload, Map.class);
	}

	private String generateCodeChallenge(String codeVerifier)
			throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
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
