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

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.Objects;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicClientRefreshTokenSupportTests {

	@Test
	void converterAcceptsPublicClientRefreshTokenRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "public-client");

		PublicClientRefreshTokenAuthenticationToken authentication = Objects.requireNonNull(
				(PublicClientRefreshTokenAuthenticationToken) new PublicClientRefreshTokenAuthenticationConverter()
					.convert(request));

		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isEqualTo("public-client");
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	void providerAuthenticatesRegisteredPublicClient() {
		RegisteredClient registeredClient = publicClient();
		var repository = new InMemoryRegisteredClientRepository(registeredClient);
		var provider = new PublicClientRefreshTokenAuthenticationProvider(repository);
		var unauthenticated = new PublicClientRefreshTokenAuthenticationToken(registeredClient.getClientId());

		PublicClientRefreshTokenAuthenticationToken authenticated = Objects
			.requireNonNull((PublicClientRefreshTokenAuthenticationToken) provider.authenticate(unauthenticated));

		assertThat(authenticated.isAuthenticated()).isTrue();
		assertThat(authenticated.getRegisteredClient()).isEqualTo(registeredClient);
	}

	@Test
	void generatorIssuesRefreshTokenForPublicAuthorizationCodeClient() {
		RegisteredClient registeredClient = publicClient();
		var clientAuthentication = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.NONE, null);
		Authentication authorizationGrant = mock(Authentication.class);
		when(authorizationGrant.getPrincipal()).thenReturn(clientAuthentication);
		OAuth2TokenContext context = mock(OAuth2TokenContext.class);
		when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
		when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
		when(context.getAuthorizationGrant()).thenReturn(authorizationGrant);
		when(context.getRegisteredClient()).thenReturn(registeredClient);

		var refreshToken = Objects.requireNonNull(new PublicClientRefreshTokenGenerator().generate(context));

		assertThat(refreshToken).isNotNull();
		assertThat(refreshToken.getExpiresAt()).isAfter(refreshToken.getIssuedAt());
	}

	private static RegisteredClient publicClient() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("public-client")
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri("https://example.com/callback")
			.build();
	}

}
