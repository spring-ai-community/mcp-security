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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * In-memory implementation of {@link McpClientRegistrationRepository} that supports
 * dynamic client registration as well as pre-registered clients.
 * <p>
 * For dynamic client registration, it first discovers metadata about the MCP Server,
 * including auth server location and required scopes, and then performs registration.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class InMemoryMcpClientRegistrationRepository implements McpClientRegistrationRepository {

	private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();

	private final Map<String, String> resources = new ConcurrentHashMap<>();

	private final DynamicClientRegistrationService clientRegistrationService;

	private final McpMetadataDiscoveryService discovery;

	public InMemoryMcpClientRegistrationRepository(DynamicClientRegistrationService clientRegistrationService,
			McpMetadataDiscoveryService discovery) {
		this.clientRegistrationService = clientRegistrationService;
		this.discovery = discovery;
	}

	@Override
	public void registerMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest) {
		this.registrations.computeIfAbsent(registrationId, id -> {
			var mcpMetadata = this.discovery.getMcpMetadata(mcpServerUrl);
			Assert.notNull(mcpMetadata.protectedResourceMetadata().authorizationServers(),
					"cannot find authorization_servers from MCP Server's protected resource metadata");
			var issuerUrl = mcpMetadata.protectedResourceMetadata().authorizationServers().get(0);
			var finalRegistrationRequest = updateScopes(registrationRequest, mcpMetadata);
			var registrationResponse = this.clientRegistrationService.register(finalRegistrationRequest, issuerUrl);
			var clientRegistration = toClientRegistration(registrationId, issuerUrl, finalRegistrationRequest,
					registrationResponse);
			this.resources.put(id, mcpMetadata.protectedResourceMetadata().resource());
			return clientRegistration;
		});
	}

	@Override
	public void addPreRegisteredClient(ClientRegistration clientRegistration, String resourceId) {
		this.registrations.computeIfAbsent(clientRegistration.getRegistrationId(), id -> {
			this.resources.put(id, resourceId);
			return clientRegistration;
		});
	}

	@Override
	@Nullable public String findResourceIdByRegistrationId(String registrationId) {
		return this.resources.get(registrationId);
	}

	@Override
	@Nullable public ClientRegistration findByRegistrationId(String registrationId) {
		return this.registrations.get(registrationId);
	}

	private DynamicClientRegistrationRequest updateScopes(DynamicClientRegistrationRequest originalRequest,
			McpMetadata mcpMetadata) {
		if (StringUtils.hasText(originalRequest.getScope())) {
			return originalRequest;
		}

		if (mcpMetadata.wwwAuthenticateParameters() != null
				&& StringUtils.hasText(mcpMetadata.wwwAuthenticateParameters().scope())) {

			return DynamicClientRegistrationRequest.from(originalRequest)
				.scope(mcpMetadata.wwwAuthenticateParameters().scope())
				.build();
		}
		else if (!CollectionUtils.isEmpty(mcpMetadata.protectedResourceMetadata().scopesSupported())) {

			return DynamicClientRegistrationRequest.from(originalRequest)
				.scope(mcpMetadata.protectedResourceMetadata().scopesSupported())
				.build();
		}

		return originalRequest;
	}

	private static ClientRegistration toClientRegistration(String registrationId, String issuerUrl,
			DynamicClientRegistrationRequest registrationRequest,
			DynamicClientRegistrationResponse registrationResponse) {
		// Slight inefficiency, as we are already fetching
		// /.well-known/oauth-authorization-server from the auth server in the
		// dynamic client registration service
		// Note that this may fail if the auth server is not reachable, but dynamic client
		// registration will fail in that case anyway.
		ClientRegistration.Builder registrationBuilder = ClientRegistrations.fromIssuerLocation(issuerUrl)
			.registrationId(registrationId);
		registrationBuilder.clientId(registrationResponse.clientId());

		if (registrationResponse.clientSecret() != null) {
			registrationBuilder.clientSecret(registrationResponse.clientSecret());
		}

		if (registrationResponse.tokenEndpointAuthMethod() != null) {
			registrationBuilder.clientAuthenticationMethod(
					new ClientAuthenticationMethod(registrationResponse.tokenEndpointAuthMethod()));
		}
		else if (registrationRequest.getTokenEndpointAuthMethod() != null) {
			registrationBuilder.clientAuthenticationMethod(registrationRequest.getTokenEndpointAuthMethod());
		}

		if (registrationResponse.grantTypes() != null && !registrationResponse.grantTypes().isEmpty()) {
			registrationBuilder
				.authorizationGrantType(new AuthorizationGrantType(registrationResponse.grantTypes().get(0)));
		}
		else if (!registrationRequest.getGrantTypes().isEmpty()) {
			registrationBuilder.authorizationGrantType(registrationRequest.getGrantTypes().get(0));
		}
		else {
			registrationBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		}

		if (registrationResponse.redirectUris() != null && !registrationResponse.redirectUris().isEmpty()) {
			registrationBuilder.redirectUri(registrationResponse.redirectUris().get(0));
		}
		else if (registrationRequest.getRedirectUris() != null && !registrationRequest.getRedirectUris().isEmpty()) {
			registrationBuilder.redirectUri(registrationRequest.getRedirectUris().get(0));
		}

		if (StringUtils.hasText(registrationResponse.scope())) {
			registrationBuilder.scope(registrationResponse.scope().split(" "));
		}
		else if (StringUtils.hasText(registrationRequest.getScope())) {
			registrationBuilder.scope(registrationRequest.getScope().split(" "));
		}

		if (registrationResponse.clientName() != null) {
			registrationBuilder.clientName(registrationResponse.clientName());
		}
		else if (registrationRequest.getClientName() != null) {
			registrationBuilder.clientName(registrationRequest.getClientName());
		}

		return registrationBuilder.build();
	}

}
