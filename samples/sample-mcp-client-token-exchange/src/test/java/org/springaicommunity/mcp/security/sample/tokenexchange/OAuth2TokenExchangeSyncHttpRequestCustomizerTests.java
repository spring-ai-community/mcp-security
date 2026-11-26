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

package org.springaicommunity.mcp.security.sample.tokenexchange;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2TokenExchangeSyncHttpRequestCustomizer}.
 *
 * @author Yeongchan Shin
 */
class OAuth2TokenExchangeSyncHttpRequestCustomizerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String TOKEN_VALUE = "test-access-token";

	private static final String TOKEN_URI = "https://auth.example.com/token";

	private static final URI ENDPOINT = URI.create("https://mcp.example.com");

	private static final String RESOURCE = "https://mcp.example.com/mcp";

	private static final Authentication AUTHENTICATION = new TestingAuthenticationToken("user", "password");

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(ENDPOINT);

	private OAuth2TokenExchangeSyncHttpRequestCustomizer customizer;

	@BeforeEach
	void setUp() {
		this.customizer = new OAuth2TokenExchangeSyncHttpRequestCustomizer(this.authorizedClientManager,
				REGISTRATION_ID);
	}

	@Test
	@DisplayName("Adds Bearer token to Authorization header")
	void addsBearerToken() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(authorizedClient(clientRegistration()));

		customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

		assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
			.hasValue("Bearer " + TOKEN_VALUE);
	}

	@Test
	@DisplayName("Uses the user authentication as the authorize request principal")
	void usesAuthenticationAsPrincipal() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(authorizedClient(clientRegistration()));

		customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

		var authorizeRequestCaptor = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		then(authorizedClientManager).should().authorize(authorizeRequestCaptor.capture());
		assertThat(authorizeRequestCaptor.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(authorizeRequestCaptor.getValue().getPrincipal()).isEqualTo(AUTHENTICATION);
	}

	@Test
	@DisplayName("Throws IllegalArgumentException when authorizedClientManager returns null")
	void authorizedClientManagerReturnsNull() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication()))
			.withMessageContaining(REGISTRATION_ID);
	}

	@Nested
	@DisplayName("Does not add authorization header")
	class NoAuthorization {

		@Test
		@DisplayName("when context is empty")
		void emptyContext() {
			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", McpTransportContext.EMPTY);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when authentication key is not an Authentication instance")
		void contextWithNonAuthenticationValue() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, "not-an-authentication"));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

	}

	@Nested
	@DisplayName("Fail on missing authentication")
	class FailOnMissingAuthentication {

		@Test
		@DisplayName("when enabled and context is empty, throws")
		void enabledAndEmptyContext() {
			customizer.failOnMissingAuthentication(true);

			assertThatIllegalStateException()
				.isThrownBy(
						() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", McpTransportContext.EMPTY))
				.withMessageContaining(REGISTRATION_ID);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when enabled and authentication is present, adds Bearer token")
		void enabledAndAuthenticationPresent() {
			customizer.failOnMissingAuthentication(true);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(clientRegistration()));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

	}

	@Nested
	@DisplayName("Token request parameters")
	class TokenRequestParameters {

		private static final String SUBJECT_TOKEN_VALUE = "incoming-user-jwt";

		private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

		@Test
		@DisplayName("sends subject_token_type=...:access_token even though the subject token is a Jwt, and resource=<MCP server>")
		void sendsAccessTokenSubjectTokenTypeAndResource() {
			var restClientBuilder = RestClient.builder().configureMessageConverters((messageConverters) -> {
				messageConverters.addCustomConverter(new FormHttpMessageConverter());
				messageConverters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
			});
			var mockServer = MockRestServiceServer.bindTo(restClientBuilder).build();

			var accessTokenResponseClient = OAuth2TokenExchangeSyncHttpRequestCustomizer
				.accessTokenResponseClient(RESOURCE);
			accessTokenResponseClient.setRestClient(restClientBuilder.build());

			mockServer.expect(MockRestRequestMatchers.requestTo(TOKEN_URI))
				.andExpect(MockRestRequestMatchers.method(HttpMethod.POST))
				.andExpect(MockRestRequestMatchers.content()
					.formDataContains(Map.of(OAuth2ParameterNames.GRANT_TYPE,
							AuthorizationGrantType.TOKEN_EXCHANGE.getValue(), OAuth2ParameterNames.SUBJECT_TOKEN,
							SUBJECT_TOKEN_VALUE, OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE,
							OAuth2ParameterNames.RESOURCE, RESOURCE)))
				.andRespond(MockRestResponseCreators.withSuccess("""
						{"access_token":"exchanged-token","token_type":"Bearer","expires_in":300}
						""", MediaType.APPLICATION_JSON));

			// Spring Security's default mapping would send this Jwt as ...:jwt
			var subjectToken = Jwt.withTokenValue(SUBJECT_TOKEN_VALUE)
				.header("alg", "none")
				.claim("sub", "test-user")
				.build();

			var tokenResponse = accessTokenResponseClient
				.getTokenResponse(new TokenExchangeGrantRequest(clientRegistration(), subjectToken, null));

			assertThat(tokenResponse.getAccessToken().getTokenValue()).isEqualTo("exchanged-token");
			mockServer.verify();
		}

		@Test
		@DisplayName("requires a resource: MCP clients must send it regardless of authorization server support")
		void requiresResource() {
			assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2TokenExchangeSyncHttpRequestCustomizer.accessTokenResponseClient(""))
				.withMessageContaining("resource");
		}

	}

	private static McpTransportContext contextWithAuthentication() {
		return McpTransportContext
			.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, AUTHENTICATION));
	}

	private static ClientRegistration clientRegistration() {
		return ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.clientId("test-client-id")
			.clientSecret("test-client-secret")
			.tokenUri(TOKEN_URI)
			.build();
	}

	private static OAuth2AuthorizedClient authorizedClient(ClientRegistration registration) {
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN_VALUE, Instant.now(),
				Instant.now().plusSeconds(300), Set.of());
		return new OAuth2AuthorizedClient(registration, "user", accessToken);
	}

}
