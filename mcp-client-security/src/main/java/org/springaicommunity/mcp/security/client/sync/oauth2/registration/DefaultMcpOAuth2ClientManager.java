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

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INSUFFICIENT_SCOPE;

/**
 * Default implementation of {@link McpOAuth2ClientManager} that delegates storage to a
 * {@link McpClientRegistrationRepository} and uses {@link McpMetadataDiscoveryService}
 * and {@link DynamicClientRegistrationService} to discover MCP server metadata and
 * perform dynamic client registration.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class DefaultMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	private static final Logger log = LoggerFactory.getLogger(DefaultMcpOAuth2ClientManager.class);

	private final McpClientRegistrationRepository repository;

	private final DynamicClientRegistrationService clientRegistrationService;

	private final McpMetadataDiscoveryService discovery;

	public DefaultMcpOAuth2ClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery) {
		Assert.notNull(repository, "repository cannot be null");
		Assert.notNull(clientRegistrationService, "clientRegistrationService cannot be null");
		Assert.notNull(discovery, "discovery cannot be null");
		this.repository = repository;
		this.clientRegistrationService = clientRegistrationService;
		this.discovery = discovery;
	}

	@Override
	public void registerMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(mcpServerUrl, "mcpServerUrl cannot be empty");
		Assert.notNull(dynamicClientRegistrationRequest, "dynamicClientRegistrationRequest cannot be null");
		if (this.repository.findByRegistrationId(registrationId) != null) {
			log.debug("Client registration [{}] already exists, skipping", registrationId);
			return;
		}
		log.debug("Registering MCP client [{}] for server [{}] via metadata discovery", registrationId, mcpServerUrl);
		var wwwAuthenticateParameters = this.discovery.getWwwAuthenticateParameters(mcpServerUrl);
		doRegisterMcpClient(registrationId, mcpServerUrl, dynamicClientRegistrationRequest, wwwAuthenticateParameters);
	}

	@Override
	public void registerMcpClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(mcpServerUrl, "mcpServerUrl cannot be empty");
		Assert.hasText(wwwAuthenticateHeader, "wwwAuthenticateHeader cannot be empty");
		Assert.notNull(dynamicClientRegistrationRequest, "dynamicClientRegistrationRequest cannot be null");
		if (this.repository.findByRegistrationId(registrationId) != null) {
			log.debug("Client registration [{}] already exists, skipping", registrationId);
			return;
		}
		log.debug("Registering MCP client [{}] for server [{}] from WWW-Authenticate header", registrationId,
				mcpServerUrl);
		var wwwAuthenticateParameters = WwwAuthenticateParameters.parse(wwwAuthenticateHeader);
		doRegisterMcpClient(registrationId, mcpServerUrl, dynamicClientRegistrationRequest, wwwAuthenticateParameters);
	}

	@Override
	public boolean updateMcpClient(String registrationId, String wwwAuthenticateHeader) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(wwwAuthenticateHeader, "wwwAuthenticateHeader cannot be empty");
		var authenticateParameters = WwwAuthenticateParameters.parse(wwwAuthenticateHeader);
		if (authenticateParameters == null) {
			log.debug("Could not parse WWW-Authenticate header [{}] for registration [{}]", wwwAuthenticateHeader,
					registrationId);
			return false;
		}
		if (!INSUFFICIENT_SCOPE.equals(authenticateParameters.getError())) {
			log.debug("WWW-Authenticate error is [{}], not insufficient_scope, skipping update for registration [{}]",
					authenticateParameters.getError(), registrationId);
			return false;
		}
		if (!StringUtils.hasText(authenticateParameters.getScope())) {
			log.debug("No scope in WWW-Authenticate header for registration [{}]", registrationId);
			return false;
		}
		var scopes = authenticateParameters.getScope().split(" ");
		if (scopes.length == 0) {
			log.debug("No scope in WWW-Authenticate header for registration [{}]", registrationId);
			return false;
		}

		log.debug("Attempting scope step-up for registration [{}] with scopes {}", registrationId,
				Arrays.asList(scopes));
		AtomicBoolean result = new AtomicBoolean(false);
		this.repository.updateClientRegistration(registrationId, builder -> {
			var existingClient = builder.build();
			if (existingClient.getScopes() == null || !existingClient.getScopes().containsAll(Arrays.asList(scopes))) {
				log.debug("Updating scopes for registration [{}]: {} -> {}", registrationId, existingClient.getScopes(),
						Arrays.asList(scopes));
				builder.scope(scopes);
				result.set(true);
			}
			else {
				log.debug("Scopes for registration [{}] already contain required scopes {}", registrationId,
						Arrays.asList(scopes));
			}
		});

		return result.get();
	}

	private void doRegisterMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest,
			@Nullable WwwAuthenticateParameters wwwAuthenticateParameters) {
		var mcpMetadata = this.discovery.getMcpMetadata(mcpServerUrl, wwwAuthenticateParameters);
		Assert.notNull(mcpMetadata.protectedResourceMetadata().authorizationServers(),
				"cannot find authorization_servers from MCP Server's protected resource metadata");
		var issuerUrl = mcpMetadata.protectedResourceMetadata().authorizationServers().get(0);
		log.debug("Discovered authorization server [{}] for registration [{}]", issuerUrl, registrationId);
		var finalRegistrationRequest = updateScopes(registrationRequest, mcpMetadata);
		log.debug("Performing dynamic client registration at [{}] for registration [{}]", issuerUrl, registrationId);
		var registrationResponse = this.clientRegistrationService.register(finalRegistrationRequest, issuerUrl);
		log.debug("Dynamic client registration successful for registration [{}], clientId=[{}]", registrationId,
				registrationResponse.clientId());
		var clientRegistration = toClientRegistration(registrationId, issuerUrl, finalRegistrationRequest,
				registrationResponse);
		this.repository.addClientRegistration(clientRegistration, mcpMetadata.protectedResourceMetadata().resource());
	}

	private DynamicClientRegistrationRequest updateScopes(DynamicClientRegistrationRequest originalRequest,
			McpMetadata mcpMetadata) {
		if (StringUtils.hasText(originalRequest.getScope())) {
			return originalRequest;
		}

		if (mcpMetadata.wwwAuthenticateParameters() != null
				&& StringUtils.hasText(mcpMetadata.wwwAuthenticateParameters().getScope())) {
			return DynamicClientRegistrationRequest.from(originalRequest)
				.scope(mcpMetadata.wwwAuthenticateParameters().getScope())
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
			registrationBuilder.clientAuthenticationMethod(
					new ClientAuthenticationMethod(registrationRequest.getTokenEndpointAuthMethod()));
		}

		if (registrationResponse.grantTypes() != null && !registrationResponse.grantTypes().isEmpty()) {
			registrationBuilder
				.authorizationGrantType(new AuthorizationGrantType(registrationResponse.grantTypes().get(0)));
		}
		else if (!registrationRequest.getGrantTypes().isEmpty()) {
			registrationBuilder
				.authorizationGrantType(new AuthorizationGrantType(registrationRequest.getGrantTypes().get(0)));
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
