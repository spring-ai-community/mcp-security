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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Default implementation of {@link McpOAuth2DcrClientManager} that delegates storage to a
 * {@link McpClientRegistrationRepository} and uses {@link McpMetadataDiscoveryService}
 * and {@link DynamicClientRegistrationService} to discover MCP server metadata and
 * perform dynamic client registration.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class DefaultMcpOAuth2DcrClientManager implements McpOAuth2DcrClientManager {

	private static final Logger log = LoggerFactory.getLogger(DefaultMcpOAuth2DcrClientManager.class);

	private final DynamicClientRegistrationService clientRegistrationService;

	private final McpMetadataDiscoveryService discovery;

	private final UrlValidator urlValidator;

	private final McpClientRegistrationRepository repository;

	private final ScopeStepUp scopeStepUp;

	private final boolean requestOfflineAccess;

	/**
	 * @deprecated use {@link DefaultMcpOAuth2DcrClientManager
	 * (McpClientRegistrationRepository, DynamicClientRegistrationService,
	 * McpMetadataDiscoveryService, UrlValidator)} instead.
	 */
	@Deprecated
	public DefaultMcpOAuth2DcrClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery) {
		this(repository, clientRegistrationService, discovery, new DefaultUrlValidator());
	}

	public DefaultMcpOAuth2DcrClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery,
			UrlValidator urlValidator) {
		this(repository, clientRegistrationService, discovery, urlValidator, false);
	}

	public DefaultMcpOAuth2DcrClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery,
			UrlValidator urlValidator, boolean requestOfflineAccess) {
		Assert.notNull(repository, "repository cannot be null");
		Assert.notNull(clientRegistrationService, "clientRegistrationService cannot be null");
		Assert.notNull(discovery, "discovery cannot be null");
		Assert.notNull(urlValidator, "urlValidator cannot be null");
		this.clientRegistrationService = clientRegistrationService;
		this.discovery = discovery;
		this.urlValidator = urlValidator;
		this.repository = repository;
		this.scopeStepUp = new ScopeStepUp(repository);
		this.requestOfflineAccess = requestOfflineAccess;
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
		return scopeStepUp.updateOAuth2ClientScopes(registrationId, wwwAuthenticateHeader);
	}

	private void doRegisterMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest,
			@Nullable WwwAuthenticateParameters wwwAuthenticateParameters) {
		var mcpMetadata = this.discovery.getMcpMetadata(mcpServerUrl, wwwAuthenticateParameters);
		Assert.notNull(mcpMetadata.protectedResourceMetadata().authorizationServers(),
				"cannot find authorization_servers from MCP Server's protected resource metadata");
		var issuerUrl = mcpMetadata.protectedResourceMetadata().authorizationServers().get(0);
		log.debug("Discovered authorization server [{}] for registration [{}]", issuerUrl, registrationId);
		var authorizationServerMetadata = this.clientRegistrationService.getAuthorizationServerMetadata(issuerUrl);
		var finalRegistrationRequest = updateRegistrationRequest(registrationRequest, mcpMetadata,
				authorizationServerMetadata);
		log.debug("Performing dynamic client registration at [{}] for registration [{}]", issuerUrl, registrationId);
		var registrationResponse = this.clientRegistrationService.register(finalRegistrationRequest,
				authorizationServerMetadata);
		log.debug("Dynamic client registration successful for registration [{}], clientId=[{}]", registrationId,
				registrationResponse.clientId());
		var clientRegistration = toClientRegistration(registrationId, authorizationServerMetadata,
				finalRegistrationRequest, registrationResponse);
		validateClientRegistration(clientRegistration);
		this.repository.addClientRegistration(clientRegistration, mcpMetadata.protectedResourceMetadata().resource());
	}

	private DynamicClientRegistrationRequest updateRegistrationRequest(DynamicClientRegistrationRequest originalRequest,
			McpMetadata mcpMetadata, ClientRegistration authorizationServerMetadata) {
		var builder = DynamicClientRegistrationRequest.from(originalRequest);
		if (!StringUtils.hasText(originalRequest.getScope()) && mcpMetadata.wwwAuthenticateParameters() != null
				&& StringUtils.hasText(mcpMetadata.wwwAuthenticateParameters().getScope())) {
			builder.scope(mcpMetadata.wwwAuthenticateParameters().getScope());
		}
		else if (!StringUtils.hasText(originalRequest.getScope())
				&& !CollectionUtils.isEmpty(mcpMetadata.protectedResourceMetadata().scopesSupported())) {
			builder.scope(mcpMetadata.protectedResourceMetadata().scopesSupported());
		}

		if (this.requestOfflineAccess
				&& originalRequest.getGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				&& supportsOfflineAccess(authorizationServerMetadata)) {
			var grantTypes = new ArrayList<>(
					originalRequest.getGrantTypes().stream().map(AuthorizationGrantType::new).toList());
			if (!originalRequest.getGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
				grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
			}
			builder.grantTypes(grantTypes);
			var scopes = new LinkedHashSet<String>();
			var scope = builder.scope;
			if (StringUtils.hasText(scope)) {
				scopes.addAll(List.of(scope.split(" ")));
			}
			scopes.add("offline_access");
			builder.scope(scopes.stream().toList());
		}

		return builder.build();
	}

	private boolean supportsOfflineAccess(ClientRegistration authorizationServerMetadata) {
		var scopesSupported = authorizationServerMetadata.getProviderDetails()
			.getConfigurationMetadata()
			.get("scopes_supported");
		return scopesSupported instanceof Collection<?> scopes && scopes.contains("offline_access");
	}

	private static ClientRegistration toClientRegistration(String registrationId,
			ClientRegistration authorizationServerMetadata, DynamicClientRegistrationRequest registrationRequest,
			DynamicClientRegistrationResponse registrationResponse) {
		ClientRegistration.Builder registrationBuilder = ClientRegistration
			.withClientRegistration(authorizationServerMetadata)
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

	private void validateClientRegistration(ClientRegistration clientRegistration) {
		var configuration = clientRegistration.getProviderDetails().getConfigurationMetadata();
		if (configuration == null) {
			return;
		}
		var uris = List.of("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri");
		for (var uri : uris) {
			var url = configuration.get(uri);
			if (url != null) {
				try {
					urlValidator.validateUrl(url.toString());
				}
				catch (InvalidUrlException e) {
					throw new IllegalStateException(String.format("Invalid %s [value=%s]: " + e.getMessage(), uri, url),
							e);
				}
			}
		}
	}

}
