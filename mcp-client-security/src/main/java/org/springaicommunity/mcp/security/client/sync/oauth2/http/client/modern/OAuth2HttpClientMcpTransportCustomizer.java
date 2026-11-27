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

import java.util.function.Function;

import io.modelcontextprotocol.modern.client.transport.HttpClientMcpTransport;
import io.modelcontextprotocol.modern.client.transport.McpHttpAuthorizationErrorHandler;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestCustomizer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

/**
 * A {@link McpClientCustomizer} for {@link HttpClientMcpTransport.Builder}, the transport
 * of the modern MCP client, that configures OAuth2 {@code authorization_code} support on
 * each transport.
 * <p>
 * For each MCP client connection, this customizer adds an
 * {@link OAuth2AuthorizationCodeRequestCustomizer} (to attach a Bearer token to outgoing
 * requests) and sets an {@link OAuth2AuthorizationErrorHandler} (to handle HTTP 401/403
 * responses, registering clients and stepping up scopes through an
 * {@link McpOAuth2ClientManager}). Both are synchronous, since obtaining a token or
 * registering a client may block, and are adapted with
 * {@link McpHttpRequestCustomizer#fromSync} and
 * {@link McpHttpAuthorizationErrorHandler#fromSync}.
 * <p>
 * The request customizer is added next to any request customizer already registered on
 * the builder. The authorization error handler replaces any handler already set, since a
 * transport has a single handler.
 * <p>
 * The OAuth2 client {@code registrationId} to use for each transport can be configured in
 * two ways:
 * <ul>
 * <li>A default registration ID, applied to all transports.
 * <li>A resolver function, mapping each transport name to a specific registration ID.
 * </ul>
 * <p>
 * By default, the customizer matches each transport to a client registration with the
 * same name.
 * <p>
 * The error handler derives the application's base URL, for the redirect URI and the CIMD
 * {@code client_id}, from the servlet request in the transport context. See
 * {@link OAuth2AuthorizationErrorHandler}.
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2AuthorizationCodeRequestCustomizer
 * @see OAuth2AuthorizationErrorHandler
 */
public class OAuth2HttpClientMcpTransportCustomizer implements McpClientCustomizer<HttpClientMcpTransport.Builder> {

	private static final Logger log = LoggerFactory.getLogger(OAuth2HttpClientMcpTransportCustomizer.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final McpOAuth2ClientManager mcpOAuth2ClientManager;

	private final Function<String, @Nullable String> registrationIdResolver;

	/**
	 * Create a customizer that uses the MCP client connection name as the OAuth2 client
	 * registration ID for each transport.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager that registers clients,
	 * for example with dynamic client registration or CIMD
	 */
	public OAuth2HttpClientMcpTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager) {
		this(authorizedClientManager, clientRegistrationRepository, mcpOAuth2ClientManager, Function.identity());
	}

	/**
	 * Create a customizer that uses the given {@code defaultRegistrationId} as the OAuth2
	 * client registration ID for all transports.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager that registers clients,
	 * for example with dynamic client registration or CIMD
	 * @param defaultRegistrationId the OAuth2 client registration ID to use for all
	 * transports
	 */
	public OAuth2HttpClientMcpTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager,
			String defaultRegistrationId) {
		this(authorizedClientManager, clientRegistrationRepository, mcpOAuth2ClientManager,
				(name) -> defaultRegistrationId);
		Assert.hasText(defaultRegistrationId, "defaultRegistrationId must not be empty");
	}

	/**
	 * Create a customizer that resolves the OAuth2 client registration ID for each
	 * transport using the provided function. The function receives the MCP client
	 * connection name and returns the registration ID to use, or {@code null} to leave
	 * the transport unchanged.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager that registers clients,
	 * for example with dynamic client registration or CIMD
	 * @param registrationIdResolver a function mapping transport names to OAuth2 client
	 * registration IDs
	 */
	public OAuth2HttpClientMcpTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager,
			Function<String, @Nullable String> registrationIdResolver) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager must not be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository must not be null");
		Assert.notNull(mcpOAuth2ClientManager, "mcpOAuth2ClientManager must not be null");
		Assert.notNull(registrationIdResolver, "registrationIdResolver must not be null");
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.mcpOAuth2ClientManager = mcpOAuth2ClientManager;
		this.registrationIdResolver = registrationIdResolver;
	}

	@Override
	public void customize(String name, HttpClientMcpTransport.Builder transportBuilder) {
		String registrationId = this.registrationIdResolver.apply(name);
		if (registrationId == null) {
			log.debug("No registration ID resolved for transport [{}], skipping OAuth2 configuration", name);
			return;
		}
		log.debug("Configuring OAuth2 for transport [{}] with registration ID [{}]", name, registrationId);

		var requestCustomizer = new OAuth2AuthorizationCodeRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, registrationId);
		var errorHandler = new OAuth2AuthorizationErrorHandler(this.mcpOAuth2ClientManager, registrationId);

		transportBuilder.requestCustomizer(McpHttpRequestCustomizer.fromSync(requestCustomizer));
		transportBuilder.authorizationErrorHandler(McpHttpAuthorizationErrorHandler.fromSync(errorHandler));
		log.debug("OAuth2 request customizer and authorization error handler configured for transport [{}]", name);
	}

}
