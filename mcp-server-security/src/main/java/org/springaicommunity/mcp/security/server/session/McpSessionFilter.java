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

package org.springaicommunity.mcp.security.server.session;

import java.io.IOException;
import java.util.function.Function;

import io.modelcontextprotocol.spec.HttpHeaders;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter for binding and validating MCP sessions.
 *
 * @author Daniel Garnier-Moiroux
 */
public class McpSessionFilter extends OncePerRequestFilter {

	private final McpSessionBindingRepository sessionBindingRepository;

	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private Function<HttpServletRequest, String> sessionBindingIdResolver = this::defaultSessionBindingIdResolver;

	public McpSessionFilter(McpSessionBindingRepository sessionBindingRepository) {
		this.sessionBindingRepository = sessionBindingRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		var requestSessionId = request.getHeader(HttpHeaders.MCP_SESSION_ID);
		var sessionBindingId = this.sessionBindingIdResolver.apply(request);
		if (StringUtils.hasText(requestSessionId)) {
			var boundUserId = this.sessionBindingRepository.findSessionBindingId(requestSessionId);
			if (boundUserId != null && !boundUserId.equals(sessionBindingId)) {
				logger.debug("Invalid session binding: User [%s] tried to access session [%s], already bound to [%s]"
					.formatted(sessionBindingId, requestSessionId, boundUserId));
				throwError(response, "invalid session binding");
				return;
			}
		}

		filterChain.doFilter(request, response);

		var responseSessionId = response.getHeader(HttpHeaders.MCP_SESSION_ID);
		if (StringUtils.hasText(responseSessionId) && StringUtils.hasText(sessionBindingId)) {
			logger.debug("Binding session [%s] to user [%s]".formatted(responseSessionId, sessionBindingId));
			try {
				this.sessionBindingRepository.bindSession(responseSessionId, sessionBindingId);
			}
			catch (InvalidMcpSessionBindingException e) {
				logger.error("Failed to bind session");
				throw new RuntimeException(e);
			}
		}
	}

	private void throwError(HttpServletResponse response, String message) throws IOException {
		response.sendError(HttpServletResponse.SC_FORBIDDEN, message);
	}

	/**
	 * Sets the resolver used to determine the session binding ID from the current
	 * context. This can be from the current {@link HttpServletRequest}, or from some
	 * thread locals.
	 * <p>
	 * Defaults to extracting the authentication's name from the {@link SecurityContext}.
	 * @param sessionBindingIdResolver the resolver to use
	 */
	public void setSessionBindingIdResolver(Function<HttpServletRequest, @Nullable String> sessionBindingIdResolver) {
		Assert.notNull(sessionBindingIdResolver, "sessionBindingIdResolver cannot be null");
		this.sessionBindingIdResolver = sessionBindingIdResolver;
	}

	public @Nullable String defaultSessionBindingIdResolver(HttpServletRequest request) {
		var authentication = SecurityContextHolder.getContext().getAuthentication();
		return this.trustResolver.isAuthenticated(authentication) ? authentication.getName() : null;
	}

}
