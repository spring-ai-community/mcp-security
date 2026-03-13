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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.http.HttpResponse;
import java.util.List;

import io.modelcontextprotocol.client.transport.customizer.McpHttpClientAuthorizationErrorHandler;
import io.modelcontextprotocol.common.McpTransportContext;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationRequest;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link McpHttpClientAuthorizationErrorHandler.Sync synchronous authorization error
 * handler} that handles HTTP 401 and 403 responses from an MCP server by performing
 * OAuth2 dynamic client registration and scope updates through
 * {@link McpOAuth2ClientManager}.
 *
 * <p>
 * On a 401 Unauthorized response, the handler performs dynamic client registration using
 * the {@code WWW-Authenticate} header. On a 403 Forbidden response with an
 * {@code insufficient_scope} error, it updates the client registration with the required
 * scopes.
 *
 * <p>
 * This performs blocking operations. It should be wrapped in a {@code Mono} subscribed on
 * a {@code boundedElastic} scheduler, which is the default in the Java SDK.
 *
 * @author Daniel Garnier-Moiroux
 * @see McpHttpClientAuthorizationErrorHandler
 * @see McpOAuth2ClientManager
 */
public class OAuth2SyncAuthorizationErrorHandler implements McpHttpClientAuthorizationErrorHandler.Sync {

	private static final Logger log = LoggerFactory.getLogger(OAuth2SyncAuthorizationErrorHandler.class);

	private static final String DEFAULT_REDIRECT_URI_TEMPLATE = "{baseUrl}/authorize/oauth2/code/{registrationId}";

	private final McpOAuth2ClientManager mcpOAuth2ClientManager;

	private final String registrationId;

	private final String mcpServerUrl;

	@Nullable private final DynamicClientRegistrationRequest dynamicClientRegistrationRequest;

	private String fallbackBaseUrl = "http://localhost:8080";

	/**
	 * Create an {@code OAuth2SyncAuthorizationErrorHandler} that will perform dynamic
	 * client registration with the {@code authorization_code} grant type and a default
	 * redirect URI template.
	 * @param mcpOAuth2ClientManager the manager to delegate registration and updates to
	 * @param registrationId the client registration identifier
	 * @param mcpServerUrl the MCP server URL
	 */
	public OAuth2SyncAuthorizationErrorHandler(McpOAuth2ClientManager mcpOAuth2ClientManager, String registrationId,
			String mcpServerUrl) {
		this(mcpOAuth2ClientManager, registrationId, mcpServerUrl, null);
	}

	/**
	 * Create an {@code OAuth2SyncAuthorizationErrorHandler} with a custom
	 * {@link DynamicClientRegistrationRequest}. When {@code null}, a default request with
	 * the {@code authorization_code} grant type will be used, and the redirect URI will
	 * be derived from the current servlet request.
	 * @param mcpOAuth2ClientManager the manager to delegate registration and updates to
	 * @param registrationId the client registration identifier
	 * @param mcpServerUrl the MCP server URL
	 * @param dynamicClientRegistrationRequest the dynamic client registration request, or
	 * {@code null} for a default request
	 */
	public OAuth2SyncAuthorizationErrorHandler(McpOAuth2ClientManager mcpOAuth2ClientManager, String registrationId,
			String mcpServerUrl, @Nullable DynamicClientRegistrationRequest dynamicClientRegistrationRequest) {
		Assert.notNull(mcpOAuth2ClientManager, "mcpOAuth2ClientManager must not be null");
		Assert.hasText(registrationId, "registrationId must not be empty");
		Assert.hasText(mcpServerUrl, "mcpServerUrl must not be empty");
		this.mcpOAuth2ClientManager = mcpOAuth2ClientManager;
		this.registrationId = registrationId;
		this.mcpServerUrl = mcpServerUrl;
		this.dynamicClientRegistrationRequest = dynamicClientRegistrationRequest;
	}

	/**
	 * Set the fallback base URL to use when the current servlet request is not available.
	 * Defaults to {@code http://localhost:8080}.
	 * @param fallbackBaseUrl the fallback base URL
	 */
	public void setFallbackBaseUrl(String fallbackBaseUrl) {
		Assert.hasText(fallbackBaseUrl, "fallbackBaseUrl must not be empty");
		this.fallbackBaseUrl = fallbackBaseUrl;
	}

	@Override
	public boolean handle(HttpResponse.ResponseInfo responseInfo, McpTransportContext context) {
		var wwwAuthenticateHeader = responseInfo.headers().firstValue("www-authenticate").orElse(null);
		if (wwwAuthenticateHeader == null) {
			log.debug("No WWW-Authenticate header found, cannot handle authorization error");
			return false;
		}

		if (responseInfo.statusCode() == HttpStatus.UNAUTHORIZED.value()) {
			return handleUnauthorized(wwwAuthenticateHeader, context);
		}
		else if (responseInfo.statusCode() == HttpStatus.FORBIDDEN.value()) {
			return handleForbidden(wwwAuthenticateHeader);
		}

		return false;
	}

	private boolean handleUnauthorized(String wwwAuthenticateHeader, McpTransportContext context) {
		log.debug("Handling 401 Unauthorized for client [{}]", this.registrationId);
		var registrationRequest = resolveRegistrationRequest(context);
		this.mcpOAuth2ClientManager.registerMcpClient(this.registrationId, this.mcpServerUrl, wwwAuthenticateHeader,
				registrationRequest);
		log.debug("Client [{}] registered, triggering authorization", this.registrationId);
		throw new ClientAuthorizationRequiredException(this.registrationId);
	}

	private boolean handleForbidden(String wwwAuthenticateHeader) {
		log.debug("Handling 403 Forbidden for client [{}]", this.registrationId);
		if (this.mcpOAuth2ClientManager.updateMcpClient(this.registrationId, wwwAuthenticateHeader)) {
			log.debug("Client [{}] scopes updated, triggering re-authorization", this.registrationId);
			throw new ClientAuthorizationRequiredException(this.registrationId);
		}
		// client unchanged, should not retry
		return false;
	}

	private DynamicClientRegistrationRequest resolveRegistrationRequest(McpTransportContext context) {
		if (this.dynamicClientRegistrationRequest != null) {
			return this.dynamicClientRegistrationRequest;
		}
		var baseUrl = resolveBaseUrl(context);
		var redirectUri = DEFAULT_REDIRECT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
			.replace("{registrationId}", this.registrationId);
		return DynamicClientRegistrationRequest.builder()
			.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE))
			.redirectUris(List.of(redirectUri))
			.build();
	}

	private String resolveBaseUrl(McpTransportContext context) {
		var requestAttributes = context.get(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY);
		if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
			var baseUrl = UriComponentsBuilder
				.fromUriString(servletRequestAttributes.getRequest().getRequestURL().toString())
				.replacePath(servletRequestAttributes.getRequest().getContextPath())
				.toUriString();
			log.debug("Resolved base URL [{}] from servlet request", baseUrl);
			return baseUrl;
		}
		log.debug("No servlet request available, using fallback base URL [{}]", this.fallbackBaseUrl);
		return this.fallbackBaseUrl;
	}

}
