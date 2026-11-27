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
package org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.OfflineAccess;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUp;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.web.OAuth2CimdEndpointFilter;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.config.Customizer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link McpOAuth2ClientManager} that registers clients with an OAuth2 Client ID
 * Metadata Document, storing clients in an {@link McpClientRegistrationRepository}. The
 * {@code client_id} is the URL of the document,
 * {@code {baseUrl}/{registrationId}/client-id-metadata.json}, served by
 * {@link OAuth2CimdEndpointFilter}.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP
 * Specification: authorization</a>
 */
public class CimdMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	private static final String DEFAULT_REDIRECT_URI_TEMPLATE = "{baseUrl}/authorize/oauth2/code/{registrationId}";

	private static final String DEFAULT_METADATA_DOCUMENT_URI_TEMPLATE = "{baseUrl}/{registrationId}/client-id-metadata.json";

	private static final String CIMD_SUPPORTED = "client_id_metadata_document_supported";

	private static final Logger log = LoggerFactory.getLogger(CimdMcpOAuth2ClientManager.class);

	private final McpMetadataDiscoveryService discoveryService;

	private final McpClientRegistrationRepository clientRegistrationRepository;

	private Customizer<ClientRegistration.Builder> clientRegistrationCustomizer = Customizer.withDefaults();

	private final UrlValidator urlValidator;

	private final ScopeStepUp scopeStepUp;

	public CimdMcpOAuth2ClientManager(McpMetadataDiscoveryService discoveryService,
			McpClientRegistrationRepository clientRegistrationRepository, UrlValidator urlValidator) {
		this.discoveryService = discoveryService;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.urlValidator = urlValidator;
		this.scopeStepUp = new ScopeStepUp(clientRegistrationRepository);
	}

	@Override
	public void registerClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException, CimdNotSupportedException {
		if (this.clientRegistrationRepository.findByRegistrationId(registrationId) != null) {
			log.debug("Client already exists {}", registrationId);
			throw new ClientAlreadyExistsException(registrationId);
		}
		var wwwAuthParams = WwwAuthenticateParameters.parse(wwwAuthenticateHeader);
		var metadata = this.discoveryService.getMcpMetadata(mcpServerUrl, wwwAuthParams);
		var builder = toClientRegistration(registrationId, metadata, baseUrl);
		this.clientRegistrationCustomizer.customize(builder);
		var clientReg = builder.build();
		validateClientRegistration(clientReg);
		log.debug("Saving client registration {}", clientReg);
		this.clientRegistrationRepository.save(clientReg, metadata.protectedResourceMetadata().resource());
	}

	@Override
	public boolean updateScopes(String registrationId, String wwwAuthenticateHeader) {
		return scopeStepUp.updateOAuth2ClientScopes(registrationId, wwwAuthenticateHeader);
	}

	/**
	 * Customize the {@link ClientRegistration}, before it is saved.
	 * @param clientRegistrationCustomizer the customizer of the client registration
	 */
	public void setClientRegistrationCustomizer(Customizer<ClientRegistration.Builder> clientRegistrationCustomizer) {
		Assert.notNull(clientRegistrationCustomizer, "clientRegistrationCustomizer must not be null");
		this.clientRegistrationCustomizer = clientRegistrationCustomizer;
	}

	private ClientRegistration.Builder toClientRegistration(String registrationId, McpMetadata mcpMetadata,
			String baseUrl) throws CimdNotSupportedException {
		Collection<String> scope = Collections.emptySet();
		if (mcpMetadata.wwwAuthenticateParameters() != null
				&& StringUtils.hasText(mcpMetadata.wwwAuthenticateParameters().getScope())) {
			scope = Arrays.asList(mcpMetadata.wwwAuthenticateParameters().getScope().split(" "));
		}
		else if (!CollectionUtils.isEmpty(mcpMetadata.protectedResourceMetadata().scopesSupported())) {
			scope = mcpMetadata.protectedResourceMetadata().scopesSupported();
		}
		Assert.notEmpty(mcpMetadata.protectedResourceMetadata().authorizationServers(),
				"Protected Resource Metadata must expose at least one authorization server");
		var issuerUrl = mcpMetadata.protectedResourceMetadata().authorizationServers().get(0);

		try {
			this.urlValidator.validateUrl(issuerUrl);
		}
		catch (InvalidUrlException e) {
			throw new IllegalStateException("Invalid authorization server URL: " + e.getMessage(), e);
		}

		var registration = ClientRegistrations.fromIssuerLocation(issuerUrl)
			.registrationId(registrationId)
			.clientId(DEFAULT_METADATA_DOCUMENT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
				.replace("{registrationId}", registrationId))
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.redirectUri(DEFAULT_REDIRECT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
				.replace("{registrationId}", registrationId))
			.scope(scope);
		var configurationMetadata = registration.build().getProviderDetails().getConfigurationMetadata();
		if (!Boolean.TRUE.equals(configurationMetadata.get(CIMD_SUPPORTED))) {
			log.debug("Authorization server {} does not advertise {}", issuerUrl, CIMD_SUPPORTED);
			throw new CimdNotSupportedException(issuerUrl);
		}
		// "no scopes" implies requesting "default scopes": we don't add offline_access
		if (scope.isEmpty() || !OfflineAccess.isSupported(configurationMetadata)) {
			return registration;
		}
		var scopes = new LinkedHashSet<>(scope);
		scopes.add(OfflineAccess.OFFLINE_ACCESS);
		return registration.scope(scopes);
	}

	private void validateClientRegistration(ClientRegistration clientRegistration) {
		var configuration = clientRegistration.getProviderDetails().getConfigurationMetadata();
		var uris = List.of("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri");
		for (var uri : uris) {
			var url = configuration.get(uri);
			if (url != null) {
				try {
					urlValidator.validateUrl(url.toString());
				}
				catch (InvalidUrlException e) {
					throw new IllegalStateException(
							String.format("Invalid %s [value=%s]: %s", uri, url, e.getMessage()), e);
				}
			}
		}
	}

}
