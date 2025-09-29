package org.springaicommunity.mcp.security.server.config;

import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationProvider;
import org.springaicommunity.mcp.security.server.apikey.web.ApiKeyAuthenticationFilter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.Assert;

public class McpApiKeyConfigurer extends AbstractHttpConfigurer<McpApiKeyConfigurer, HttpSecurity> {

	private ApiKeyEntityRepository<?> apiKeyEntityRepository;

	private String headerName;

	private AuthenticationConverter authenticationConverter;

	@Override
	public void init(HttpSecurity http) throws Exception {
		http.authenticationProvider(new ApiKeyAuthenticationProvider<>(this.apiKeyEntityRepository))
			// TODO: improve matcher to check for API key
			.csrf(csrf -> csrf.ignoringRequestMatchers("/mcp"));
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		Assert.notNull(this.apiKeyEntityRepository, "apiKeyRepository must not be null");

		var authManager = http.getSharedObject(AuthenticationManager.class);

		var filter = new ApiKeyAuthenticationFilter(authManager);
		if (this.headerName != null) {
			filter.setApiKeyHeader(this.headerName);
		}
		if (this.authenticationConverter != null) {
			filter.setAuthenticationConverter(this.authenticationConverter);
		}
		http.addFilterBefore(filter, BasicAuthenticationFilter.class);
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
	 * Overrides the value from {@link #authenticationConverter(AuthenticationConverter)}.
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
	 *      return ApiKeyAuthenticationToken.unauthenicated(apiKey);
	 *  };
	 * </pre>
	 * <p>
	 * Overrides the value from {@link #headerName(String)}.
	 */
	public McpApiKeyConfigurer authenticationConverter(AuthenticationConverter authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	public static McpApiKeyConfigurer mcpServerApiKey() {
		return new McpApiKeyConfigurer();
	}

}
