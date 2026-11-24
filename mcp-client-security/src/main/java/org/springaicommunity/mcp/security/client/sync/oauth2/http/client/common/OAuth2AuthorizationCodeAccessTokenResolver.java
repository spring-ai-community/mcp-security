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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common;

import java.util.Collection;
import java.util.Collections;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.client.transport.McpHttpAuthorizationErrorHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.OfflineAccess;

import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;

/**
 * FOR INTERNAL USE ONLY.
 * <p>
 * Resolves the user's OAuth2 access token, obtained with the {@code authorization_code}
 * grant, from an {@link McpTransportContext}.
 * <p>
 * Internal class used by both the legacy and the modern transport. It reads the
 * {@link org.springframework.security.core.Authentication} and the servlet request from
 * the transport context, see {@link AuthenticationMcpTransportContextProvider}, and
 * passes the servlet request and response to the {@link OAuth2AuthorizedClientManager}.
 * <p>
 * Tokens cannot be resolved outside the context of an HTTP Servlet Request, because this
 * customizer supports {@link DefaultOAuth2AuthorizedClientManager} which supports
 * anonymous users. Anonymous users get their tokens stored in the session. Returns null
 * and the request proceeds without an authorization header.
 * <p>
 * When the client registration doesn't exist yet (dynamic registration, CIMD), it returns
 * {@code null}, so that the request is sent without a token. The MCP server responds with
 * HTTP {@code 401} and that response is handled by
 * {@link McpHttpAuthorizationErrorHandler}.
 * <p>
 * When the client registration has more scopes than the token, it signals a scope step up
 * scenario, which requires requesting a new token. Throws
 * {@link ClientAuthorizationRequiredException} in that case.
 *
 * @author Daniel Garnier-Moiroux
 */
public final class OAuth2AuthorizationCodeAccessTokenResolver {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationCodeAccessTokenResolver.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final String clientRegistrationId;

	private boolean failOnMissingClientRegistration = false;

	public OAuth2AuthorizationCodeAccessTokenResolver(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, String clientRegistrationId) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.clientRegistrationId = clientRegistrationId;
	}

	/**
	 * Resolve the access token for the user in the transport context.
	 * @param context the transport context of the outgoing MCP request
	 * @return the access token, or {@code null} when the request should be sent without
	 * one
	 * @throws ClientAuthorizationRequiredException when the user must authorize
	 * @throws IllegalArgumentException when the registration is missing and
	 * {@link #setFailOnMissingClientRegistration(boolean)} is {@code true}, or when the
	 * manager does not support authorizing the client
	 */
	public @Nullable OAuth2AccessToken resolve(McpTransportContext context) {
		var authentication = AuthenticationMcpTransportContextProvider.getAuthentication(context);
		var requestAttributes = AuthenticationMcpTransportContextProvider.getRequestAttributes(context);
		if (authentication == null || requestAttributes == null) {
			log.debug("No authentication or request context found: not requesting token");
			return null;
		}

		var registration = this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId);
		if (registration == null) {
			if (this.failOnMissingClientRegistration) {
				throw new IllegalArgumentException(
						"Client registration [" + this.clientRegistrationId + "] does not exist");
			}
			log.debug("Client [{}] does not exist. It may be dynamically registered at a later point, skipping.",
					this.clientRegistrationId);
			return null;
		}

		var authorizeRequestBuilder = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistrationId)
			.principal(authentication)
			.attribute(HttpServletRequest.class.getName(), requestAttributes.getRequest());
		if (requestAttributes.getResponse() != null) {
			authorizeRequestBuilder.attribute(HttpServletResponse.class.getName(), requestAttributes.getResponse());
		}

		log.debug("Requesting access token for client [{}]", this.clientRegistrationId);
		var authorizedClient = authorize(authorizeRequestBuilder.build());
		if (authorizedClient == null) {
			throw new IllegalArgumentException(
					"Authorization not supported for client [" + this.clientRegistrationId + "]");
		}
		log.debug("Client [{}] is authorized", this.clientRegistrationId);

		var accessToken = authorizedClient.getAccessToken();
		Collection<String> scopes = registration.getScopes() == null ? Collections.emptyList()
				: registration.getScopes()
					.stream()
					// offline_access is a special case, which signals requesting a
					// refresh_token, not an authorization scope. Does not require scope
					// step up.
					.filter(scope -> !OfflineAccess.OFFLINE_ACCESS.equals(scope))
					.toList();
		if (accessToken.getScopes() != null && !scopes.isEmpty() && !accessToken.getScopes().containsAll(scopes)) {
			// For the access token to have scopes, it's likely the client registration
			// has scopes - otherwise they are not requested in the first place.
			log.debug("Existing token scopes {} do not match requested scopes {}. Requesting a new token.",
					accessToken.getScopes(), scopes);
			throw new ClientAuthorizationRequiredException(this.clientRegistrationId);
		}
		log.debug("Token scopes match requested scopes {}", scopes);
		return accessToken;
	}

	private @Nullable OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
		try {
			return this.authorizedClientManager.authorize(authorizeRequest);
		}
		catch (ClientAuthorizationException ex) {
			// Within authorize(), for authorization_code clients, invalid_grant can only
			// come from the refresh_token grant: the refresh token is expired or revoked.
			if (OAuth2ErrorCodes.INVALID_GRANT.equals(ex.getError().getErrorCode())) {
				log.debug("Refresh token rejected for client [{}]. Re-authorizing.", this.clientRegistrationId);
				throw new ClientAuthorizationRequiredException(this.clientRegistrationId);
			}
			throw ex;
		}
	}

	/**
	 * Fail when the client registration is missing. Defaults to {@code false}, to support
	 * Dynamic Client Registration (DCR) and Client ID Metadata Documents (CIMD).
	 * <p>
	 * Set to {@code true} for pre-registered clients.
	 * @param failOnMissingClientRegistration defaults to {@code false}
	 */
	public void setFailOnMissingClientRegistration(boolean failOnMissingClientRegistration) {
		this.failOnMissingClientRegistration = failOnMissingClientRegistration;
	}

}
