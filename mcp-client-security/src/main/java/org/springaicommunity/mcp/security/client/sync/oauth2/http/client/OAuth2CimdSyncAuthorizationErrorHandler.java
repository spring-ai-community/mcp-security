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

import io.modelcontextprotocol.client.transport.customizer.McpHttpClientAuthorizationErrorHandler;
import io.modelcontextprotocol.common.McpTransportContext;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.DefaultMcpOAuth2CimdClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.McpOAuth2CimdClientManager;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link McpHttpClientAuthorizationErrorHandler.Sync} synchronous authorization error
 * handler that handles HTTP 401 and HTTP with CIMD clients and scope step-up through
 * {@link DefaultMcpOAuth2CimdClientManager}.
 *
 * <p>
 * On a 401 Unauthorized response, the handler registers a CIMD client, with information
 * from the {@code WWW-Authenticate} header. On a 403 Forbidden response with an
 * {@code insufficient_scope} error, it updates the client registration with the required
 * scopes.
 *
 * <p>
 * This performs blocking operations. It should be wrapped in a {@code Mono} subscribed on
 * a {@code boundedElastic} scheduler, which is the default in the Java SDK.
 *
 * @author Daniel Garnier-Moiroux
 * @see McpHttpClientAuthorizationErrorHandler
 * @see DefaultMcpOAuth2CimdClientManager
 */
public class OAuth2CimdSyncAuthorizationErrorHandler implements McpHttpClientAuthorizationErrorHandler.Sync {

	private static final Logger log = LoggerFactory.getLogger(OAuth2CimdSyncAuthorizationErrorHandler.class);

	private final String registrationId;

	private final String mcpServerUrl;

	private @Nullable String fallbackBaseUrl = null;

	private final McpOAuth2CimdClientManager mcpCimdClientManager;

	/**
	 * Build an {@link OAuth2CimdSyncAuthorizationErrorHandler} instance.
	 * @param mcpCimdClientManager the CIMD service
	 * @param registrationId the registration ID that will be used to represent the client
	 * registration associated with this handler
	 * @param mcpServerUrl URL of the MCP server
	 */
	public OAuth2CimdSyncAuthorizationErrorHandler(McpOAuth2CimdClientManager mcpCimdClientManager,
			String registrationId, String mcpServerUrl) {
		this.registrationId = registrationId;
		this.mcpServerUrl = mcpServerUrl;
		this.mcpCimdClientManager = mcpCimdClientManager;
	}

	/**
	 * The base URL of the MCP client, in case the URL of the current request is not
	 * available in the {@link McpTransportContext}.
	 * @param fallbackBaseUrl the URL
	 */
	public void setFallbackBaseUrl(String fallbackBaseUrl) {
		Assert.notNull(fallbackBaseUrl, "fallbackBaseUrl cannot be null");
		this.fallbackBaseUrl = fallbackBaseUrl;
	}

	@Override
	public boolean handle(HttpResponse.ResponseInfo responseInfo, McpTransportContext context) {
		var wwwAuthenticateHeader = responseInfo.headers().firstValue("www-authenticate").orElse(null);
		if (wwwAuthenticateHeader == null) {
			log.debug("No WWW-Authenticate header found, cannot handle authorization error");
		}
		else if (responseInfo.statusCode() == HttpStatus.UNAUTHORIZED.value()) {
			handleUnauthorized(wwwAuthenticateHeader, context);
		}
		else if (responseInfo.statusCode() == HttpStatus.FORBIDDEN.value()) {
			handleForbidden(wwwAuthenticateHeader);
		}

		return false;
	}

	private void handleUnauthorized(String wwwAuthenticateHeader, McpTransportContext context) {
		log.debug("Handling 401 Unauthorized for client [{}]", this.registrationId);
		var baseUrl = this.resolveBaseUrl(context);
		if (baseUrl == null) {
			log.debug("Could not determine base URL for request");
			return;
		}
		try {
			this.mcpCimdClientManager.createClient(this.registrationId, this.mcpServerUrl, wwwAuthenticateHeader,
					baseUrl);
		}
		catch (ClientAlreadyExistsException e) {
			log.debug("Client [{}] already exists, not expecting HTTP 401 from the server", this.registrationId);
			return;
		}
		log.debug("CIMD client created [{}] registered, triggering authorization", this.registrationId);
		// client changed, retry
		throw new ClientAuthorizationRequiredException(this.registrationId);
	}

	private void handleForbidden(String wwwAuthenticateHeader) {
		log.debug("Handling 403 Forbidden for client [{}]", this.registrationId);
		if (this.mcpCimdClientManager.updateClient(this.registrationId, wwwAuthenticateHeader)) {
			log.debug("Client [{}] scopes updated, triggering re-authorization", this.registrationId);
			// client changed, retry
			throw new ClientAuthorizationRequiredException(this.registrationId);
		}
	}

	private @Nullable String resolveBaseUrl(McpTransportContext context) {
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
