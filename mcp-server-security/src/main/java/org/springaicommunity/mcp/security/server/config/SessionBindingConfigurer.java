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

package org.springaicommunity.mcp.security.server.config;

import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.session.InMemoryMcpSessionBindingRepository;
import org.springaicommunity.mcp.security.server.session.McpSessionBindingRepository;
import org.springaicommunity.mcp.security.server.session.McpSessionFilter;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.util.StringUtils;

/**
 * An {@link AbstractHttpConfigurer} for configuring MCP Session Binding.
 * <p>
 * This configurer registers an {@link McpSessionFilter} that binds an MCP Session ID to a
 * specific user identifier, as per Security Best Practices. When a session is
 * established, the session is bound to the principal's name (user id, client id, etc).
 * Subsequent calls using that Session ID must be made by the same user/client.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#mitigation-4">Security
 * best practices</a>
 */
public final class SessionBindingConfigurer extends AbstractHttpConfigurer<SessionBindingConfigurer, HttpSecurity> {

	@Nullable private McpSessionBindingRepository sessionBindingRepository;

	@Nullable private Function<HttpServletRequest, String> sessionBindingIdResolver;

	@Override
	public void init(HttpSecurity http) {
		McpSessionFilter filter = new McpSessionFilter(getSessionBindingRepository(http));
		if (this.sessionBindingIdResolver != null) {
			filter.setSessionBindingIdResolver(this.sessionBindingIdResolver);
		}
		http.addFilterAfter(filter, AuthorizationFilter.class);
	}

	/**
	 * Use this {@link McpSessionBindingRepository} as the backing repository for session
	 * bindings.
	 * @param sessionBindingRepository the repository used for storing session bindings.
	 * @return The {@link SessionBindingConfigurer} for further configuration.
	 */
	public SessionBindingConfigurer sessionBindingRepository(McpSessionBindingRepository sessionBindingRepository) {
		this.sessionBindingRepository = sessionBindingRepository;
		return this;
	}

	/**
	 * Set the resolver used to extract the Session Binding ID from the context. This
	 * could be the current OAuth2 Token {@code sub} claim, the API key id, etc.
	 * @param sessionBindingIdResolver the resolver
	 * @return The {@link SessionBindingConfigurer} for further configuration.
	 */
	public SessionBindingConfigurer sessionBindingIdResolver(
			Function<HttpServletRequest, String> sessionBindingIdResolver) {
		this.sessionBindingIdResolver = sessionBindingIdResolver;
		return this;
	}

	private McpSessionBindingRepository getSessionBindingRepository(HttpSecurity http) {
		if (this.sessionBindingRepository != null) {
			http.setSharedObject(McpSessionBindingRepository.class, this.sessionBindingRepository);
			return this.sessionBindingRepository;
		}
		McpSessionBindingRepository sessionBindingRepository = http.getSharedObject(McpSessionBindingRepository.class);
		if (sessionBindingRepository == null) {
			sessionBindingRepository = getOptionalBean(http, McpSessionBindingRepository.class);
			if (sessionBindingRepository == null) {
				sessionBindingRepository = new InMemoryMcpSessionBindingRepository();
			}
			http.setSharedObject(McpSessionBindingRepository.class, sessionBindingRepository);
		}
		return sessionBindingRepository;
	}

	/**
	 * Lifted from
	 * {@code org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ConfigurerUtils}.
	 */
	@Nullable private static <T> T getOptionalBean(HttpSecurity http, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(http.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

}
