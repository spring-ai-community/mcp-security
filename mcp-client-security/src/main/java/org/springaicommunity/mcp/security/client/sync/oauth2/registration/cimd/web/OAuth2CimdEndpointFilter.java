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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.web;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationParameterNames;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that processes OAuth 2.0 Client ID Metadata Document Requests.
 *
 * @see <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">OAuth
 * 2.0 Client ID Metadata Document</a>
 */
public final class OAuth2CimdEndpointFilter extends OncePerRequestFilter {

	private static final String DEFAULT_METADATA_DOCUMENT_PATH = "/{registrationId}/client-id-metadata.json";

	private static final String CLIENT_ID_TEMPLATE = "{baseUrl}" + DEFAULT_METADATA_DOCUMENT_PATH;

	private static final String REDIRECT_URI_TEMPLATE = "{baseUrl}/authorize/oauth2/code/{registrationId}";

	private static final List<String> DEFAULT_GRANT_TYPES = List.of("authorization_code", "refresh_token");

	private static final String DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = ClientAuthenticationMethod.NONE.getValue();

	private static final List<String> RESPONSE_TYPES = List.of("code");

	private RequestMatcher requestMatcher;

	private final HttpMessageConverter<Object> messageConverter;

	private Consumer<Map<String, Object>> metadataCustomizer = (cimd) -> {
	};

	private @Nullable String baseUrl;

	public OAuth2CimdEndpointFilter() {
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, DEFAULT_METADATA_DOCUMENT_PATH);
		this.messageConverter = HttpMessageConverters.getJsonMessageConverter();
	}

	public void setMetadataCustomizer(Consumer<Map<String, Object>> metadataCustomizer) {
		Assert.notNull(metadataCustomizer, "metadataCustomizer cannot be null");
		this.metadataCustomizer = metadataCustomizer;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public void setBaseUrl(String baseUrl) {
		Assert.notNull(baseUrl, "baseUrl cannot be null");
		this.baseUrl = baseUrl;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		var baseUrl = resolveBaseUrl(request);
		var registrationId = this.requestMatcher.matcher(request).getVariables().get("registrationId");
		Map<String, Object> cimd = new LinkedHashMap<>();
		cimd.put(DynamicClientRegistrationParameterNames.TOKEN_ENDPOINT_AUTH_METHOD,
				DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD);
		cimd.put(DynamicClientRegistrationParameterNames.GRANT_TYPES, DEFAULT_GRANT_TYPES);
		cimd.put(DynamicClientRegistrationParameterNames.RESPONSE_TYPES, RESPONSE_TYPES);
		cimd.put(OAuth2ParameterNames.CLIENT_ID,
				CLIENT_ID_TEMPLATE.replace("{baseUrl}", baseUrl).replace("{registrationId}", registrationId));
		cimd.put(DynamicClientRegistrationParameterNames.REDIRECT_URIS, List
			.of(REDIRECT_URI_TEMPLATE.replace("{baseUrl}", baseUrl).replace("{registrationId}", registrationId)));
		cimd.put(DynamicClientRegistrationParameterNames.CLIENT_NAME, "Spring client for " + registrationId);
		this.metadataCustomizer.accept(cimd);

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.messageConverter.write(cimd, MediaType.APPLICATION_JSON, httpResponse);
	}

	private String resolveBaseUrl(HttpServletRequest request) {
		if (this.baseUrl != null) {
			return this.baseUrl;
		}
		return UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
			.replacePath(null)
			.replaceQuery(null)
			.fragment(null)
			.toUriString();
	}

}
