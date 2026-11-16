/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.client.sync.config;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link McpClientOAuth2Configurer}.
 */
class McpClientOAuth2ConfigurerTests {

	private static final String RESOURCE = "https://mcp.example.com/mcp";

	private static final String TOKEN_URI = "https://auth.example.com/oauth2/token";

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final ClientRegistration registration = ClientRegistration.withRegistrationId("test")
		.clientId("test-client")
		.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.redirectUri("https://app.example.com/callback")
		.authorizationUri("https://auth.example.com/oauth2/authorize")
		.tokenUri(TOKEN_URI)
		.build();

	@Test
	void refreshTokenClientIncludesResourceParameter() {
		this.repository.addClientRegistration(this.registration, RESOURCE);
		var builder = restClientBuilder();
		var server = MockRestServiceServer.bindTo(builder).build();

		var expectedParams = new LinkedMultiValueMap<String, String>();
		expectedParams.add("grant_type", "refresh_token");
		expectedParams.add("client_id", "test-client");
		expectedParams.add("refresh_token", "test-refresh-token");
		expectedParams.add("resource", RESOURCE);

		server.expect(requestTo(TOKEN_URI))
			.andExpect(method(HttpMethod.POST))
			.andExpect(content().formData(expectedParams))
			.andRespond(
					withSuccess("{\"access_token\":\"refreshed-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
							MediaType.APPLICATION_JSON));

		var client = McpClientOAuth2Configurer.mcpRefreshTokenTokenResponseClient(this.repository);
		client.setRestClient(builder.build());

		var tokenResponse = client.getTokenResponse(refreshTokenGrantRequest());

		assertThat(tokenResponse.getAccessToken().getTokenValue()).isEqualTo("refreshed-token");
		server.verify();
	}

	@Test
	void refreshTokenClientOmitsResourceParameterWhenNull() {
		this.repository.addClientRegistration(this.registration, null);
		var builder = restClientBuilder();
		var server = MockRestServiceServer.bindTo(builder).build();

		var expectedParams = new LinkedMultiValueMap<String, String>();
		expectedParams.add("grant_type", "refresh_token");
		expectedParams.add("client_id", "test-client");
		expectedParams.add("refresh_token", "test-refresh-token");

		server.expect(requestTo(TOKEN_URI))
			.andExpect(method(HttpMethod.POST))
			.andExpect(content().formData(expectedParams))
			.andRespond(
					withSuccess("{\"access_token\":\"refreshed-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
							MediaType.APPLICATION_JSON));

		var client = McpClientOAuth2Configurer.mcpRefreshTokenTokenResponseClient(this.repository);
		client.setRestClient(builder.build());

		var tokenResponse = client.getTokenResponse(refreshTokenGrantRequest());

		assertThat(tokenResponse.getAccessToken().getTokenValue()).isEqualTo("refreshed-token");
		server.verify();
	}

	@Test
	@SuppressWarnings("NullAway") // intentionally passing null to verify it is rejected
	void nullRepositoryThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> McpClientOAuth2Configurer.mcpTokenRequestParametersConverter(null));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> McpClientOAuth2Configurer.mcpRefreshTokenTokenResponseClient(null));
	}

	private static RestClient.Builder restClientBuilder() {
		return RestClient.builder()
			.configureMessageConverters(converters -> converters.addCustomConverter(new FormHttpMessageConverter())
				.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter()));
	}

	private OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest() {
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired-token",
				Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
		var refreshToken = new OAuth2RefreshToken("test-refresh-token", Instant.now().minusSeconds(120));
		return new OAuth2RefreshTokenGrantRequest(this.registration, accessToken, refreshToken);
	}

}
