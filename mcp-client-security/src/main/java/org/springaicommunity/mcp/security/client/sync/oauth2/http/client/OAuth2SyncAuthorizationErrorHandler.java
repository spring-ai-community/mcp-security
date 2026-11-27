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

import io.modelcontextprotocol.client.transport.HttpRequestSnapshot;
import io.modelcontextprotocol.client.transport.customizer.McpHttpClientTransportAuthorizationErrorHandler;
import io.modelcontextprotocol.common.McpTransportContext;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientRegistrationNotSupportedException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link McpHttpClientTransportAuthorizationErrorHandler.Sync} synchronous
 * authorization error handler that handles HTTP 401 and 403 responses from an MCP server
 * by registering clients and updating scopes through an {@link McpOAuth2ClientManager}.
 *
 * <p>
 * On a 401 Unauthorized response, the handler registers a client with information from
 * the {@code WWW-Authenticate} header. How the client is registered depends on the
 * {@link McpOAuth2ClientManager}: for example dynamic client registration, or a client ID
 * metadata document (CIMD). On a 403 Forbidden response with an
 * {@code insufficient_scope} error, it updates the client registration with the required
 * scopes.
 *
 * <p>
 * This performs blocking operations. It should be wrapped in a {@code Mono} subscribed on
 * a {@code boundedElastic} scheduler, which is the default in the Java SDK.
 *
 * @author Daniel Garnier-Moiroux
 * @see McpHttpClientTransportAuthorizationErrorHandler
 * @see McpOAuth2ClientManager
 */
public class OAuth2SyncAuthorizationErrorHandler implements McpHttpClientTransportAuthorizationErrorHandler.Sync {

	private static final Logger log = LoggerFactory.getLogger(OAuth2SyncAuthorizationErrorHandler.class);

	private final McpOAuth2ClientManager mcpOAuth2ClientManager;

	private final String registrationId;

	private @Nullable String fallbackBaseUrl = null;

	/**
	 * Create an {@code OAuth2SyncAuthorizationErrorHandler}.
	 * @param mcpOAuth2ClientManager the manager to delegate registration and scope
	 * updates to
	 * @param registrationId the registration ID that will be used to represent the client
	 * registration associated with this handler
	 */
	public OAuth2SyncAuthorizationErrorHandler(McpOAuth2ClientManager mcpOAuth2ClientManager, String registrationId) {
		Assert.notNull(mcpOAuth2ClientManager, "mcpOAuth2ClientManager must not be null");
		Assert.hasText(registrationId, "registrationId must not be empty");
		this.mcpOAuth2ClientManager = mcpOAuth2ClientManager;
		this.registrationId = registrationId;
	}

	/**
	 * Set the base URL of the MCP client, used when the current servlet request is not
	 * available in the {@link McpTransportContext}. The base URL is passed to the
	 * {@link McpOAuth2ClientManager}, which uses it to build the redirect URI and, with
	 * CIMD, the {@code client_id}.
	 * <p>
	 * There is no default value. With CIMD, the {@code client_id} is the URL of the
	 * client ID metadata document, and the authorization server must be able to fetch it.
	 * A default such as {@code http://localhost:8080} would produce a {@code client_id}
	 * that the authorization server cannot resolve. When this is not set and no servlet
	 * request is available, HTTP 401 responses are not handled.
	 * <p>
	 * With CIMD, this must match the base URL served by the
	 * {@link org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.web.OAuth2CimdEndpointFilter}.
	 * @param fallbackBaseUrl the fallback base URL
	 */
	public void setFallbackBaseUrl(String fallbackBaseUrl) {
		Assert.hasText(fallbackBaseUrl, "fallbackBaseUrl must not be empty");
		this.fallbackBaseUrl = fallbackBaseUrl;
	}

	@Override
	public boolean handle(HttpRequestSnapshot requestSnapshot, HttpResponse.ResponseInfo responseInfo,
			McpTransportContext context) {
		var wwwAuthenticateHeader = responseInfo.headers().firstValue("www-authenticate").orElse(null);
		if (wwwAuthenticateHeader == null) {
			log.debug("No WWW-Authenticate header found, cannot handle authorization error");
		}
		else if (responseInfo.statusCode() == HttpStatus.UNAUTHORIZED.value()) {
			handleUnauthorized(requestSnapshot.requestUri().toString(), wwwAuthenticateHeader, context);
		}
		else if (responseInfo.statusCode() == HttpStatus.FORBIDDEN.value()) {
			handleForbidden(wwwAuthenticateHeader);
		}

		return false;
	}

	private void handleUnauthorized(String mcpServerUrl, String wwwAuthenticateHeader, McpTransportContext context) {
		log.debug("Handling 401 Unauthorized for client [{}]", this.registrationId);
		var baseUrl = resolveBaseUrl(context);
		if (baseUrl == null) {
			log.debug("Could not determine base URL for request");
			return;
		}
		try {
			this.mcpOAuth2ClientManager.registerClient(this.registrationId, mcpServerUrl, wwwAuthenticateHeader,
					baseUrl);
		}
		catch (ClientAlreadyExistsException e) {
			log.debug("Client [{}] already exists, not expecting HTTP 401 from the server", this.registrationId);
			return;
		}
		catch (ClientRegistrationNotSupportedException e) {
			log.debug("Client [{}] not registered for MCP server at {}: {}", this.registrationId, mcpServerUrl,
					e.getMessage());
			return;
		}
		log.debug("Client [{}] registered, triggering authorization", this.registrationId);
		// client changed, retry
		throw new ClientAuthorizationRequiredException(this.registrationId);
	}

	private void handleForbidden(String wwwAuthenticateHeader) {
		log.debug("Handling 403 Forbidden for client [{}]", this.registrationId);
		if (this.mcpOAuth2ClientManager.updateScopes(this.registrationId, wwwAuthenticateHeader)) {
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
