package org.springframework.security.oauth2.server.authorization.token;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;

/**
 * Unconditionally add the resource claim to the access token.
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
			String authorizationRequestResource = (String) authorizationRequest.getAdditionalParameters()
				.get(RESOURCE_PARAM_NAME);

			context.getClaims().claim(JwtClaimNames.AUD, authorizationRequestResource);

		}
		else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())
				&& context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {

			OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = context
				.getAuthorizationGrant();
			String resource = (String) clientCredentialsAuthentication.getAdditionalParameters()
				.get(RESOURCE_PARAM_NAME);

			context.getClaims().claim(JwtClaimNames.AUD, resource);
		}

	}

}
