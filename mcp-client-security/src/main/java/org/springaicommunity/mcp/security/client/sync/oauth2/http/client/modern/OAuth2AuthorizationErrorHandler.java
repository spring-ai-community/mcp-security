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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.client.transport.McpHttpAuthorizationErrorHandler;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpResponseInfo;
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
 * Handles {@code 401} and {@code 403} answers of an MCP server for a modern client,
 * through an {@link McpOAuth2ClientManager}.
 * <ul>
 * <li>On a {@code 401}, it obtains a client from the manager, then throws
 * {@link ClientAuthorizationRequiredException}. When the client already exists, or the
 * manager does not support the authorization server, it returns {@code false}.</li>
 * <li>On a {@code 403} with {@code insufficient_scope}, it adds the scopes to the
 * registration, then throws {@link ClientAuthorizationRequiredException}. Without new
 * scopes, it returns {@code false}.</li>
 * </ul>
 * {@link ClientAuthorizationRequiredException} reaches the caller of the MCP client
 * unwrapped. When the handler returns {@code false}, the request fails with the
 * transport's {@code McpHttpStatusException}.
 * <p>
 * To use a Client ID Metadata Document when the authorization server supports it, and
 * Dynamic Client Registration otherwise, as the MCP specification recommends, use a
 * {@link org.springaicommunity.mcp.security.client.sync.oauth2.registration.DelegatingMcpOAuth2ClientManager}.
 * <p>
 * Registration blocks, so set it through
 * {@link McpHttpAuthorizationErrorHandler#fromSync}:
 *
 * <pre>
 * HttpClientMcpTransport.builder(serverUrl)
 *     .authorizationErrorHandler(McpHttpAuthorizationErrorHandler.fromSync(handler))
 *     .build();
 * </pre>
 * <p>
 * The server URI is the request's. The base URL of the application, used for the redirect
 * URI and the CIMD {@code client_id}, comes from the servlet request in the transport
 * context, as put there by {@link AuthenticationMcpTransportContextProvider}. Without a
 * servlet request, the handler uses the fallback base URL (see
 * {@link #setFallbackBaseUrl(String)}).
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationErrorHandler implements McpHttpAuthorizationErrorHandler.Sync {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationErrorHandler.class);

	private final McpOAuth2ClientManager clientManager;

	private final String registrationId;

	private @Nullable String fallbackBaseUrl = null;

	/**
	 * @param clientManager the client manager
	 * @param registrationId the client registration ID
	 */
	public OAuth2AuthorizationErrorHandler(McpOAuth2ClientManager clientManager, String registrationId) {
		Assert.notNull(clientManager, "clientManager cannot be null");
		Assert.hasText(registrationId, "registrationId cannot be empty");
		this.clientManager = clientManager;
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
		this.fallbackBaseUrl = fallbackBaseUrl.endsWith("/")
				? fallbackBaseUrl.substring(0, fallbackBaseUrl.length() - 1) : fallbackBaseUrl;
	}

	@Override
	public boolean handle(McpHttpRequest request, McpHttpResponseInfo response, McpTransportContext context) {
		var wwwAuthenticateHeader = response.headers().firstValue("www-authenticate").orElse(null);
		if (wwwAuthenticateHeader == null) {
			log.debug("No WWW-Authenticate header on {} for {}, cannot handle it", response, request);
			return false;
		}
		if (response.statusCode() == HttpStatus.UNAUTHORIZED.value()) {
			return handleUnauthorized(request.uri().toString(), wwwAuthenticateHeader, context);
		}
		if (response.statusCode() == HttpStatus.FORBIDDEN.value()) {
			return handleForbidden(wwwAuthenticateHeader);
		}
		return false;
	}

	private boolean handleUnauthorized(String serverUrl, String wwwAuthenticateHeader, McpTransportContext context) {
		log.debug("Handling 401 for client [{}]", this.registrationId);
		var baseUrl = resolveBaseUrl(context);
		if (baseUrl == null) {
			log.debug("Could not determine the base URL for client [{}], not handling the 401", this.registrationId);
			return false;
		}
		try {
			this.clientManager.registerClient(this.registrationId, serverUrl, wwwAuthenticateHeader, baseUrl);
		}
		catch (ClientAlreadyExistsException ex) {
			log.debug("Client [{}] already exists, not handling the 401", this.registrationId);
			return false;
		}
		catch (ClientRegistrationNotSupportedException ex) {
			log.debug("Client [{}] not registered for MCP server at {}: {}", this.registrationId, serverUrl,
					ex.getMessage());
			return false;
		}
		log.debug("Client [{}] registered, the user must authorize it", this.registrationId);
		throw new ClientAuthorizationRequiredException(this.registrationId);
	}

	private boolean handleForbidden(String wwwAuthenticateHeader) {
		log.debug("Handling 403 for client [{}]", this.registrationId);
		if (this.clientManager.updateScopes(this.registrationId, wwwAuthenticateHeader)) {
			log.debug("Client [{}] scopes updated, the user must authorize it again", this.registrationId);
			throw new ClientAuthorizationRequiredException(this.registrationId);
		}
		return false;
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
