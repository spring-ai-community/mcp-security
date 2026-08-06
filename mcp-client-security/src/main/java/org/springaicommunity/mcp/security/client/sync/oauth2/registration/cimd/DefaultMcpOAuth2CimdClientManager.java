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
import java.util.List;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUp;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Default implementation for {@link McpOAuth2CimdClientManager}, storing clients in an
 * {@link McpClientRegistrationRepository}.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP
 * Specification: authorization</a>
 */
public class DefaultMcpOAuth2CimdClientManager implements McpOAuth2CimdClientManager {

	private static final String DEFAULT_REDIRECT_URI_TEMPLATE = "{baseUrl}/authorize/oauth2/code/{registrationId}";

	private static final String DEFAULT_METADATA_DOCUMENT_URI_TEMPLATE = "{baseUrl}/{registrationId}/client-id-metadata.json";

	private static final Logger log = LoggerFactory.getLogger(DefaultMcpOAuth2CimdClientManager.class);

	private final McpMetadataDiscoveryService discoveryService;

	private final McpClientRegistrationRepository clientRegistrationRepository;

	private Function<ClientRegistration, ClientRegistration> clientRegistrationCustomizer = Function.identity();

	private final UrlValidator urlValidator;

	private final ScopeStepUp scopeStepUp;

	public DefaultMcpOAuth2CimdClientManager(McpMetadataDiscoveryService discoveryService,
			McpClientRegistrationRepository clientRegistrationRepository, UrlValidator urlValidator) {
		this.discoveryService = discoveryService;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.urlValidator = urlValidator;
		this.scopeStepUp = new ScopeStepUp(clientRegistrationRepository);
	}

	@Override
	public void createClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException {
		if (this.clientRegistrationRepository.findByRegistrationId(registrationId) != null) {
			log.debug("Client already exists {}", registrationId);
			throw new ClientAlreadyExistsException(registrationId);
		}
		var metadata = this.discoveryService.getMcpMetadata(mcpServerUrl,
				WwwAuthenticateParameters.parse(wwwAuthenticateHeader));
		var clientReg = this.clientRegistrationCustomizer
			.apply(toClientRegistration(registrationId, metadata, baseUrl));
		validateClientRegistration(clientReg);
		log.debug("Adding client registration {}", clientReg);
		this.clientRegistrationRepository.addClientRegistration(clientReg,
				metadata.protectedResourceMetadata().resource());
	}

	@Override
	public boolean updateClient(String registrationId, String wwwAuthenticateHeader) {
		return scopeStepUp.updateOAuth2ClientScopes(registrationId, wwwAuthenticateHeader);
	}

	public void setClientRegistrationCustomizer(
			Function<ClientRegistration, ClientRegistration> clientRegistrationCustomizer) {
		Assert.notNull(clientRegistrationCustomizer, "clientRegistrationCustomizer must not be null");
		this.clientRegistrationCustomizer = clientRegistrationCustomizer;
	}

	private ClientRegistration toClientRegistration(String registrationId, McpMetadata mcpMetadata, String baseUrl) {
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

		return ClientRegistrations.fromIssuerLocation(issuerUrl)
			.registrationId(registrationId)
			.clientId(DEFAULT_METADATA_DOCUMENT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
				.replace("{registrationId}", registrationId))
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.redirectUri(DEFAULT_REDIRECT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
				.replace("{registrationId}", registrationId))
			.scope(scope)
			.build();
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
