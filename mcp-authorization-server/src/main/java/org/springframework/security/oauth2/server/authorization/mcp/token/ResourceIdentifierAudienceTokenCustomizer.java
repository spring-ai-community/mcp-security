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

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Unconditionally add the resource claim to the access token.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ResourceIdentifierAudienceTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private static final String RESOURCE_PARAM_NAME = "resource";

	@Override
	public void customize(JwtEncodingContext context) {
		if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)
				&& context.getAuthorizedScopes().contains(OidcScopes.OPENID)) {
			// No customizations needed for access tokens in OpenID Connect flow
			return;
		}

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
				&& context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {

			OAuth2AuthorizationRequest authorizationRequest = context.getAuthorization()
				.getAttribute(OAuth2AuthorizationRequest.class.getName());
			String resource = (String) authorizationRequest.getAdditionalParameters().get(RESOURCE_PARAM_NAME);

			if (resource != null) {
				context.getClaims().claim(JwtClaimNames.AUD, resource);
			}
		}
		else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())
				&& context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {

			OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = context
				.getAuthorizationGrant();
			String resource = (String) clientCredentialsAuthentication.getAdditionalParameters()
				.get(RESOURCE_PARAM_NAME);
			if (resource != null) {
				context.getClaims().claim(JwtClaimNames.AUD, resource);
			}
		}
		// resource identifier as aud claim to access token during refresh token grant
		else if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
			OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication = context.getAuthorizationGrant();
			String resource = (String) refreshTokenAuthentication.getAdditionalParameters().get(RESOURCE_PARAM_NAME);
			if (resource != null) {
				context.getClaims().claim(JwtClaimNames.AUD, resource);
			}
		}

	}

}
