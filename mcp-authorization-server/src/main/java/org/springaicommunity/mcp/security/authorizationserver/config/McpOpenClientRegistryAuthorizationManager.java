package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientRegistrationEndpointFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Workaround to enhance {@link McpAuthorizationServerConfigurer} so that it opens the
 * Dynamic Client Registration endpoint and allows every request.
 * <p>
 * This is required for two reasons. First, the
 * {@link OAuth2ClientRegistrationEndpointFilter} is set after the
 * {@link AuthorizationFilter}, so authorization rules apply. Second, authorization rules
 * are defined by the end-user, and cannot be overridden in a configurer.
 * <p>
 * Ideally, this should be removed once the registration can be configured as "public".
 *
 * @author Daniel Garnier-Moiroux
 */
class McpOpenClientRegistryAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

	private final AuthorizationManager<HttpServletRequest> delegate;

	// TODO: use AuthorizationServerSettings
	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.POST, "/oauth2/register");

	public McpOpenClientRegistryAuthorizationManager(AuthorizationManager<HttpServletRequest> delegate) {
		this.delegate = delegate;
	}

	@Override
	public @Nullable AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			HttpServletRequest request) {
		if (requestMatcher.matches(request)) {
			return new AuthorizationDecision(true);
		}
		return delegate.authorize(authentication, request);
	}

	public static ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> postProcessor() {
		return new ObjectPostProcessor<>() {
			@Override
			public <O extends AuthorizationManager<HttpServletRequest>> O postProcess(O manager) {
				return ((O) new McpOpenClientRegistryAuthorizationManager(manager));
			}
		};
	}

}
