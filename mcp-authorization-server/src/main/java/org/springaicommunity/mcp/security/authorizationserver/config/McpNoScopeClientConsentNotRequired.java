package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.function.Predicate;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;

/**
 * Customizer for {@link OAuth2AuthorizationCodeRequestAuthenticationProvider}, that
 * removes the need for consent when a client was registered with 0 scopes. Otherwise, the
 * user cannot get past the consent screen with no scopes present.
 *
 * @see <a href=
 * "https://github.com/spring-projects/spring-security/issues/18565">spring-security/issues/18565</a>
 * @author Daniel Garnier-Moiroux
 */
class McpNoScopeClientConsentNotRequired implements Predicate<OAuth2AuthorizationCodeRequestAuthenticationContext> {

	@Override
	public boolean test(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		if (!authenticationContext.getRegisteredClient().getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}
		if (authenticationContext.getAuthorizationRequest().getScopes().isEmpty()) {
			return false;
		}
		// 'openid' scope does not require consent
		if (authenticationContext.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)
				&& authenticationContext.getAuthorizationRequest().getScopes().size() == 1) {
			return false;
		}

		if (authenticationContext.getAuthorizationConsent() != null && authenticationContext.getAuthorizationConsent()
			.getScopes()
			.containsAll(authenticationContext.getAuthorizationRequest().getScopes())) {
			return false;
		}

		return true;
	}

	public static ObjectPostProcessor<OAuth2AuthorizationCodeRequestAuthenticationProvider> postProcessor() {
		return new ObjectPostProcessor<>() {
			@Override
			public <O extends OAuth2AuthorizationCodeRequestAuthenticationProvider> O postProcess(
					O authenticationProvider) {
				authenticationProvider.setAuthorizationConsentRequired(new McpNoScopeClientConsentNotRequired());
				return authenticationProvider;
			}
		};
	}

}
