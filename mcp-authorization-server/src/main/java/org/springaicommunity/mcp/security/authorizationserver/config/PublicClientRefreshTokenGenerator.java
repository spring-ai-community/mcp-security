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

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

import org.jspecify.annotations.Nullable;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

	private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private final Clock clock = Clock.systemUTC();

	@Override
	public @Nullable OAuth2RefreshToken generate(OAuth2TokenContext context) {
		Authentication authorizationGrant = context.getAuthorizationGrant();
		if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())
				|| !AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
				|| authorizationGrant == null
				|| !(authorizationGrant.getPrincipal() instanceof OAuth2ClientAuthenticationToken client)
				|| !ClientAuthenticationMethod.NONE.equals(client.getClientAuthenticationMethod())) {
			return null;
		}

		Instant issuedAt = this.clock.instant();
		Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
		return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
	}

}
