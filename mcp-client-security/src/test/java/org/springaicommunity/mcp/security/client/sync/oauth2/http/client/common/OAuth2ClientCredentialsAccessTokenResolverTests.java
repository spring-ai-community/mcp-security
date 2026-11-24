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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2ClientCredentialsAccessTokenResolver}.
 *
 * @author Daniel Garnier-Moiroux
 */
class OAuth2ClientCredentialsAccessTokenResolverTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String TOKEN_VALUE = "test-access-token";

	private final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager = mock(
			AuthorizedClientServiceOAuth2AuthorizedClientManager.class);

	private final OAuth2ClientCredentialsAccessTokenResolver resolver = new OAuth2ClientCredentialsAccessTokenResolver(
			this.authorizedClientManager, REGISTRATION_ID);

	@Test
	void returnsAccessToken() {
		when(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(authorizedClient());

		var accessToken = this.resolver.resolve();

		assertThat(accessToken.getTokenValue()).isEqualTo(TOKEN_VALUE);
	}

	@Test
	void authorizesClientUnderFixedPrincipal() {
		when(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(authorizedClient());

		this.resolver.resolve();

		var captor = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		verify(this.authorizedClientManager).authorize(captor.capture());
		assertThat(captor.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(captor.getValue().getPrincipal().getName()).isEqualTo("mcp-client-service");
	}

	@Test
	void authorizedClientManagerReturnsNull() {
		when(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(null);

		assertThatIllegalArgumentException().isThrownBy(this.resolver::resolve).withMessageContaining(REGISTRATION_ID);
	}

	@Test
	void authorizationFailure() {
		when(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).thenThrow(
				new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), REGISTRATION_ID));

		assertThatExceptionOfType(ClientAuthorizationException.class).isThrownBy(this.resolver::resolve)
			.satisfies(ex -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT));
	}

	private static OAuth2AuthorizedClient authorizedClient() {
		var registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientId("test-client-id")
			.tokenUri("https://auth.example.com/token")
			.build();
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN_VALUE, Instant.now(),
				Instant.now().plusSeconds(300));
		return new OAuth2AuthorizedClient(registration, "mcp-client-service", accessToken);
	}

}
