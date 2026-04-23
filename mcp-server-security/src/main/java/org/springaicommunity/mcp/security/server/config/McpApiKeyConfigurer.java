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

package org.springaicommunity.mcp.security.server.config;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationProvider;
import org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationConverter;
import org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationFilter;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpApiKeyConfigurer extends AbstractHttpConfigurer<McpApiKeyConfigurer, HttpSecurity> {

	private @Nullable ApiKeyEntityRepository<?> apiKeyEntityRepository;

	private @Nullable String headerName;

	private @Nullable AuthenticationConverter authenticationConverter;

	public @Nullable SessionBindingConfigurer sessionBindingConfigurer;

	@Override
	public void init(HttpSecurity http) {
		Assert.notNull(this.apiKeyEntityRepository, "apiKeyRepository cannot be null");
		http.authenticationProvider(postProcess(new ApiKeyAuthenticationProvider<>(this.apiKeyEntityRepository)));
		http.exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
		registerCsrfOverride(http);
		if (this.sessionBindingConfigurer != null) {
			this.sessionBindingConfigurer.init(http);
		}
	}

	@Override
	public void configure(HttpSecurity http) {
		Assert.notNull(this.apiKeyEntityRepository, "apiKeyRepository must not be null");

		var authManager = http.getSharedObject(AuthenticationManager.class);

		var authenticationConverter = getAuthenticationConverter();
		var filter = new ApiKeyAuthenticationFilter(authManager, postProcess(authenticationConverter));
		http.addFilterBefore(postProcess(filter), BasicAuthenticationFilter.class);
	}

	private AuthenticationConverter getAuthenticationConverter() {
		if (this.authenticationConverter != null) {
			return this.authenticationConverter;
		}
		if (StringUtils.hasText(this.headerName)) {
			return new ApiKeyAuthenticationConverter(this.headerName);
		}
		return new ApiKeyAuthenticationConverter();
	}

	/**
	 * REQUIRED: The repository for storing API keys.
	 */
	public McpApiKeyConfigurer apiKeyRepository(ApiKeyEntityRepository<?> apiKeyEntityRepository) {
		this.apiKeyEntityRepository = apiKeyEntityRepository;
		return this;
	}

	/**
	 * The name of the header from which to extract the API key. Defaults to
	 * {@link org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationFilter#DEFAULT_API_KEY_HEADER}.
	 * <p>
	 * If {@link #authenticationConverter(AuthenticationConverter)} is set, then this is
	 * ignored.
	 */
	public McpApiKeyConfigurer headerName(String headerName) {
		this.headerName = headerName;
		return this;
	}

	/**
	 * Method for extracting an API key from an HTTP request.
	 * <p>
	 * For example: <pre>
	 *  request -> {
	 *      var headerValue = request.getHeader("Authorization");
	 *      if (!StringUtils.hasText(headerValue)
	 *      || !headerValue.contains("Bearer ")) {
	 *          return null;
	 *      }
	 *      var tokenValue = headerValue.replace("Bearer ", "");
	 *      var apiKey = ApiKeyImpl.from(tokenValue);
	 *      return ApiKeyAuthenticationToken.unauthenticated(apiKey);
	 *  };
	 * </pre>
	 * <p>
	 * Overrides the value from {@link #headerName(String)}.
	 */
	public McpApiKeyConfigurer authenticationConverter(AuthenticationConverter authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Enable binding a specific MCP Session to a given user/client identifier, as per
	 * Security Best Practices. When a session is established with a client sending an API
	 * key, the session is bound to the principal's name, by default the
	 * {@link ApiKeyEntity#getId()}.
	 * @param sessionBindingCustomizer customizer for session bindings configuration
	 * @return The {@link McpApiKeyConfigurer} for further configuration
	 * @see <a href=
	 * "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#mitigation-4">Security
	 * best practices</a>
	 */
	public McpApiKeyConfigurer sessionBinding(Customizer<SessionBindingConfigurer> sessionBindingCustomizer) {
		if (this.sessionBindingConfigurer == null) {
			this.sessionBindingConfigurer = new SessionBindingConfigurer();
		}
		sessionBindingCustomizer.customize(sessionBindingConfigurer);
		return this;
	}

	private void registerCsrfOverride(HttpSecurity http) {
		var csrf = http.getConfigurer(CsrfConfigurer.class);
		if (csrf != null) {
			var authenticationConverter = this.getAuthenticationConverter();
			csrf.ignoringRequestMatchers(req -> authenticationConverter.convert(req) != null);
		}
	}

	public static McpApiKeyConfigurer mcpServerApiKey() {
		return new McpApiKeyConfigurer();
	}

}
