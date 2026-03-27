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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2AuthorizationCodeSyncHttpRequestCustomizer}.
 *
 * @author Daniel Garnier-Moiroux
 */
class OAuth2AuthorizationCodeSyncHttpRequestCustomizerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String TOKEN_VALUE = "test-access-token";

	private static final URI ENDPOINT = URI.create("https://mcp.example.com");

	private static final Authentication AUTHENTICATION = new TestingAuthenticationToken("user", "password");

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);

	private final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(ENDPOINT);

	private OAuth2AuthorizationCodeSyncHttpRequestCustomizer customizer;

	private final ServletRequestAttributes requestAttributes = new ServletRequestAttributes(
			mock(HttpServletRequest.class), mock(HttpServletResponse.class));

	@BeforeEach
	void setUp() {
		this.customizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, REGISTRATION_ID);
	}

	@Test
	@DisplayName("Adds Bearer token to Authorization header")
	void addsBearerToken() {
		var registration = clientRegistration().build();
		given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(authorizedClient(registration));

		customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

		assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
			.hasValue("Bearer " + TOKEN_VALUE);
	}

	@Test
	@DisplayName("Throws IllegalArgumentException when authorizedClientManager returns null")
	void authorizedClientManagerReturnsNull() {
		var registration = clientRegistration().build();
		given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
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
		@DisplayName("when context has no authentication key")
		void contextWithRequestAttributesOnly() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, requestAttributes));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when context has authentication but no request attributes")
		void contextWithAuthenticationOnly() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, AUTHENTICATION));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when authentication key is not an Authentication instance")
		void contextWithNonAuthenticationValue() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, "not-an-authentication",
						AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, requestAttributes));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when request attributes is not a ServletRequestAttributes")
		void contextWithNonServletRequestAttributes() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, AUTHENTICATION,
						AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, "not-request-attrs"));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

	}

	@Nested
	class DynamicClientRegistration {

		@Test
		@DisplayName("when client registration does not exist, skips authorization")
		void registrationNotFound() {
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(null);

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
		}

		@Test
		@DisplayName("when dynamic client registration is disabled and registration does not exist, throws")
		void disabledAndRegistrationNotFound() {
			customizer.disableDynamicClientRegistration(true);
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(null);

			assertThatIllegalArgumentException()
				.isThrownBy(
						() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication()))
				.withMessageContaining(REGISTRATION_ID);
		}

	}

	@Nested
	@DisplayName("Scope step up flow")
	class ScopeStepUp {

		@Test
		@DisplayName("Adds Bearer token when registration has no scopes")
		void noScopesInRegistration() {
			var registration = clientRegistration().build();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("read", "write")));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

		@Test
		@DisplayName("Adds Bearer token when token scopes cover all registration scopes")
		void tokenScopesCoverRegistrationScopes() {
			var registration = clientRegistration().scope("read", "write").build();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("read", "write", "admin")));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

		@Test
		@DisplayName("Adds Bearer token when registration has null scopes")
		void registrationHasNullScopes() {
			var registration = clientRegistrationWithNullScopes();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("read")));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

		@Test
		@DisplayName("Adds Bearer token when token scopes exactly match registration scopes")
		void tokenScopesExactlyMatchRegistrationScopes() {
			var registration = clientRegistration().scope("read", "write").build();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("read", "write")));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

		@Test
		@DisplayName("Throws ClientAuthorizationRequiredException when token is missing required scopes")
		void scopeMismatch() {
			var registration = clientRegistration().scope("read", "write").build();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("read")));

			assertThatThrownBy(
					() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication()))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
		}

		@Test
		@DisplayName("Throws ClientAuthorizationRequiredException when token has completely different scopes")
		void completelyDifferentScopes() {
			var registration = clientRegistration().scope("read", "write").build();
			given(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID)).willReturn(registration);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(registration, Set.of("admin")));

			assertThatThrownBy(
					() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication()))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
		}

	}

	private McpTransportContext contextWithAuthentication() {
		return McpTransportContext
			.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, AUTHENTICATION,
					AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY, this.requestAttributes));
	}

	private static ClientRegistration.Builder clientRegistration() {
		return ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientId("test-client-id")
			.redirectUri("https://example.com/callback")
			.authorizationUri("https://auth.example.com/authorize")
			.tokenUri("https://auth.example.com/token");
	}

	private static OAuth2AuthorizedClient authorizedClient(ClientRegistration registration) {
		return authorizedClient(registration, Set.of());
	}

	private static OAuth2AuthorizedClient authorizedClient(ClientRegistration registration, Set<String> scopes) {
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				OAuth2AuthorizationCodeSyncHttpRequestCustomizerTests.TOKEN_VALUE, Instant.now(),
				Instant.now().plusSeconds(300), scopes);
		return new OAuth2AuthorizedClient(registration, "user", accessToken);
	}

	private static ClientRegistration clientRegistrationWithNullScopes() {
		ClientRegistration registration = mock(ClientRegistration.class);
		given(registration.getRegistrationId()).willReturn(REGISTRATION_ID);
		given(registration.getScopes()).willReturn(null);
		return registration;
	}

}
