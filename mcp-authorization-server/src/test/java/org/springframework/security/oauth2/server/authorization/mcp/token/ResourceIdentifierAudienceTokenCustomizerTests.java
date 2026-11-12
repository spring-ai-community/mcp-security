/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.mcp.token;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link ResourceIdentifierAudienceTokenCustomizer}, in particular the
 * refresh_token grant, which must not let a client-supplied {@code resource} parameter
 * escalate the {@code aud} claim beyond what was granted in the original authorization.
 */
class ResourceIdentifierAudienceTokenCustomizerTests {

	private static final String RESOURCE_PARAM_NAME = "resource";

	private final ResourceIdentifierAudienceTokenCustomizer customizer = new ResourceIdentifierAudienceTokenCustomizer();

	@Test
	void authorizationCodeGrantSetsAudienceFromRequestedResource() {
		RegisteredClient registeredClient = registeredClient();
		Authentication authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken("code",
				mock(Authentication.class), null, Map.of(RESOURCE_PARAM_NAME, "https://resource-x.example.com"));

		JwtEncodingContext context = contextBuilder(registeredClient).authorizationGrant(authorizationGrant).build();

		this.customizer.customize(context);

		Object audience = context.getClaims().build().getClaim(JwtClaimNames.AUD);
		assertThat(audience).isEqualTo("https://resource-x.example.com");
	}

	@Test
	void refreshTokenGrantIgnoresClientSuppliedResourceAndReusesOriginalAudience() {
		RegisteredClient registeredClient = registeredClient();
		OAuth2Authorization authorization = authorizationWithAccessTokenAudience(registeredClient,
				"https://resource-x.example.com");
		Authentication authorizationGrant = new OAuth2RefreshTokenAuthenticationToken("refresh-token",
				mock(Authentication.class), null, Map.of(RESOURCE_PARAM_NAME, "https://resource-y.example.com"));

		JwtEncodingContext context = contextBuilder(registeredClient).authorization(authorization)
			.authorizationGrant(authorizationGrant)
			.build();

		this.customizer.customize(context);

		Object audience = context.getClaims().build().getClaim(JwtClaimNames.AUD);
		assertThat(audience).isEqualTo("https://resource-x.example.com");
	}

	@Test
	void refreshTokenGrantDoesNotIntroduceAudienceWhenOriginalHadNone() {
		RegisteredClient registeredClient = registeredClient();
		OAuth2Authorization authorization = authorizationWithAccessTokenAudience(registeredClient, null);
		Authentication authorizationGrant = new OAuth2RefreshTokenAuthenticationToken("refresh-token",
				mock(Authentication.class), null, Map.of(RESOURCE_PARAM_NAME, "https://resource-y.example.com"));

		JwtEncodingContext context = contextBuilder(registeredClient).authorization(authorization)
			.authorizationGrant(authorizationGrant)
			.build();

		this.customizer.customize(context);

		Object audience = context.getClaims().build().getClaim(JwtClaimNames.AUD);
		assertThat(audience).isNull();
	}

	private static RegisteredClient registeredClient() {
		return RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("test-client")
			.clientSecret("{noop}test-secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri("https://client.example.com/callback")
			.scope("mcp.read")
			.build();
	}

	private static OAuth2Authorization authorizationWithAccessTokenAudience(RegisteredClient registeredClient,
			String audience) {
		Instant issuedAt = Instant.now();
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				issuedAt, issuedAt.plusSeconds(300));

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
			.principalName("user")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

		if (audience != null) {
			builder.token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
					Map.of(JwtClaimNames.AUD, audience)));
		}
		else {
			builder.token(accessToken);
		}

		return builder.build();
	}

	private static JwtEncodingContext.Builder contextBuilder(RegisteredClient registeredClient) {
		JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject("user");
		return (JwtEncodingContext.Builder) JwtEncodingContext
			.with(JwsHeader.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256), claims)
			.registeredClient(registeredClient)
			.tokenType(OAuth2TokenType.ACCESS_TOKEN)
			.authorizedScopes(Set.of("mcp.read"));
	}

}
