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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Collection;
import java.util.Collections;

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * An {@link McpSyncHttpClientRequestCustomizer} that adds an OAuth2 access token to
 * outgoing MCP client HTTP requests using the {@code authorization_code} grant type.
 * <p>
 * This customizer is intended for MCP client authorization scenarios where the client
 * acts on behalf of an authenticated end user. It retrieves an access token via the
 * {@link OAuth2AuthorizedClientManager} and attaches it as a {@code Bearer} token in the
 * {@code Authorization} header of each outgoing MCP request.
 * <p>
 * If the current token's scopes do not cover all scopes required by the
 * {@link ClientRegistrationRepository client registration}, a
 * {@link ClientAuthorizationRequiredException} is thrown to trigger re-authorization
 * (e.g. scope step-up).
 * <p>
 * If the client registration does not exist yet (e.g. it is registered dynamically), the
 * request is sent without a token. The MCP server will respond with an HTTP 401, and
 * {@link OAuth2SyncAuthorizationErrorHandler} will handle that response to perform
 * dynamic client registration before retrying.
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2SyncAuthorizationErrorHandler
 */
public class OAuth2AuthorizationCodeSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationCodeSyncHttpRequestCustomizer.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final String clientRegistrationId;

	private final ClientRegistrationRepository clientRegistrationRepository;

	public OAuth2AuthorizationCodeSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, String clientRegistrationId) {
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.clientRegistrationId = clientRegistrationId;
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		if (!(context
			.get(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY) instanceof Authentication authentication)
				|| !(context.get(
						AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY) instanceof ServletRequestAttributes requestAttributes)) {
			log.debug("No authentication or request context found: not requesting token");
			return;
		}

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientRegistrationId)
			.principal(authentication)
			.attribute(HttpServletRequest.class.getName(), requestAttributes.getRequest())
			.attribute(HttpServletResponse.class.getName(), requestAttributes.getResponse())
			.build();
		log.debug("Requesting access token for client [{}]", this.clientRegistrationId);

		var registration = this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId);
		if (registration == null) {
			log.debug("Client [{}] does not exist. It may be dynamically registered at a later point, skipping.",
					this.clientRegistrationId);
			return;
		}

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient == null) {
			throw new IllegalArgumentException(
					"Authorization not supported for client [" + this.clientRegistrationId + "]");
		}
		log.debug("Client [{}] is authorized", this.clientRegistrationId);

		Collection<String> scopes = registration.getScopes() != null ? registration.getScopes()
				: Collections.emptyList();
		if (authorizedClient.getAccessToken().getScopes() != null && !scopes.isEmpty()
				&& !authorizedClient.getAccessToken().getScopes().containsAll(scopes)) {
			// For the access token to have scopes, it's likely the client registration
			// has scopes - otherwise they are not requested in the first place.
			log.debug("Existing token scopes {} do not match requested scopes {}. Requesting a new token.",
					authorizedClient.getAccessToken().getScopes(), scopes);
			throw new ClientAuthorizationRequiredException(this.clientRegistrationId);
		}
		else {
			log.debug("Token scopes match requested scopes {}", scopes);
		}
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		log.debug("Adding token to header");
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

}
