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

import java.lang.reflect.Field;
import java.util.function.Function;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpHttpClientAuthorizationErrorHandler;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

/**
 * A {@link McpClientCustomizer} for {@link HttpClientStreamableHttpTransport.Builder}
 * that configures OAuth2 {@code authorization_code} support on each transport.
 * <p>
 * For each MCP client connection, this customizer applies an
 * {@link OAuth2AuthorizationCodeSyncHttpRequestCustomizer} (to attach a Bearer token to
 * outgoing requests) and an {@link OAuth2SyncAuthorizationErrorHandler} (to handle HTTP
 * 401/403 responses, including dynamic client registration).
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
 * The MCP server URL is extracted from the transport builder's {@code baseUri} and
 * {@code endpoint} fields.
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2AuthorizationCodeSyncHttpRequestCustomizer
 * @see OAuth2SyncAuthorizationErrorHandler
 */
public class OAuth2HttpClientTransportCustomizer
		implements McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> {

	private static final Logger log = LoggerFactory.getLogger(OAuth2HttpClientTransportCustomizer.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final McpOAuth2ClientManager mcpOAuth2ClientManager;

	private final Function<String, @Nullable String> registrationIdResolver;

	/**
	 * Create a customizer that uses the MCP client connection name as the OAuth2 client
	 * registration ID for each transport.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager for dynamic
	 * registration
	 */
	public OAuth2HttpClientTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager) {
		this(authorizedClientManager, clientRegistrationRepository, mcpOAuth2ClientManager, Function.identity());
	}

	/**
	 * Create a customizer that uses the given {@code defaultRegistrationId} as the OAuth2
	 * client registration ID for all transports.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager for dynamic
	 * registration
	 * @param defaultRegistrationId the OAuth2 client registration ID to use for all
	 * transports
	 */
	public OAuth2HttpClientTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager,
			String defaultRegistrationId) {
		this(authorizedClientManager, clientRegistrationRepository, mcpOAuth2ClientManager,
				(name) -> defaultRegistrationId);
		Assert.hasText(defaultRegistrationId, "defaultRegistrationId must not be empty");
	}

	/**
	 * Create a customizer that resolves the OAuth2 client registration ID for each
	 * transport using the provided function. The function receives the MCP client
	 * connection name and must return the registration ID to use.
	 * @param authorizedClientManager the authorized client manager
	 * @param clientRegistrationRepository the client registration repository
	 * @param mcpOAuth2ClientManager the MCP OAuth2 client manager for dynamic
	 * registration
	 * @param registrationIdResolver a function mapping transport names to OAuth2 client
	 * registration IDs
	 */
	public OAuth2HttpClientTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
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
	public void customize(String name, HttpClientStreamableHttpTransport.Builder transportBuilder) {
		String registrationId = this.registrationIdResolver.apply(name);
		if (registrationId == null) {
			log.debug("No registration ID resolved for transport [{}], skipping OAuth2 configuration", name);
			return;
		}
		log.debug("Configuring OAuth2 for transport [{}] with registration ID [{}]", name, registrationId);
		// This is a hack until the mcp server url is passed to the error handler.
		String mcpServerUrl = extractMcpServerUrl(transportBuilder);
		log.debug("Extracted MCP server URL [{}] for transport [{}]", mcpServerUrl, name);

		var requestCustomizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(this.authorizedClientManager,
				this.clientRegistrationRepository, registrationId);
		// TODO: make manager nullable...?
		var errorHandler = new OAuth2SyncAuthorizationErrorHandler(this.mcpOAuth2ClientManager, registrationId,
				mcpServerUrl);

		transportBuilder.httpRequestCustomizer(requestCustomizer)
			.authorizationErrorHandler(McpHttpClientAuthorizationErrorHandler.fromSync(errorHandler));
		log.debug("OAuth2 request customizer and authorization error handler configured for transport [{}]", name);
	}

	private static String extractMcpServerUrl(HttpClientStreamableHttpTransport.Builder builder) {
		String baseUri = extractField(builder, "baseUri", String.class);
		String endpoint = extractField(builder, "endpoint", String.class);
		if (baseUri.endsWith("/") && endpoint.startsWith("/")) {
			return baseUri + endpoint.substring(1);
		}
		return baseUri + endpoint;
	}

	private static <T> T extractField(Object target, String fieldName, Class<T> type) {
		Field field = ReflectionUtils.findField(target.getClass(), fieldName);
		if (field == null) {
			throw new IllegalStateException(
					"Could not find field '%s' on %s".formatted(fieldName, target.getClass().getName()));
		}
		ReflectionUtils.makeAccessible(field);
		Object value = ReflectionUtils.getField(field, target);
		Assert.notNull(value,
				() -> "Field '%s' on %s must not be null".formatted(fieldName, target.getClass().getName()));
		return type.cast(value);
	}

}
