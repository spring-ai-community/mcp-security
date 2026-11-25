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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
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
 * An {@link McpOAuth2ClientManager} that obtains clients with OAuth2 Dynamic Client
 * Registration. It delegates storage to a {@link McpClientRegistrationRepository} and
 * uses {@link McpMetadataDiscoveryService} and {@link DynamicClientRegistrationService}
 * to discover MCP server metadata and perform dynamic client registration.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class DcrMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	private static final Logger log = LoggerFactory.getLogger(DcrMcpOAuth2ClientManager.class);

	private static final String DEFAULT_REDIRECT_URI_TEMPLATE = "{baseUrl}/authorize/oauth2/code/{registrationId}";

	private final DynamicClientRegistrationService clientRegistrationService;

	private final McpMetadataDiscoveryService discovery;

	private final UrlValidator urlValidator;

	private final McpClientRegistrationRepository repository;

	private final ScopeStepUp scopeStepUp;

	private Customizer<DynamicClientRegistrationRequest.Builder> registrationRequestCustomizer = Customizer
		.withDefaults();

	private Customizer<ClientRegistration.Builder> clientRegistrationCustomizer = Customizer.withDefaults();

	/**
	 * @deprecated use {@link DcrMcpOAuth2ClientManager (McpClientRegistrationRepository,
	 * DynamicClientRegistrationService, McpMetadataDiscoveryService, UrlValidator)}
	 * instead.
	 */
	@Deprecated
	public DcrMcpOAuth2ClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery) {
		this(repository, clientRegistrationService, discovery, new DefaultUrlValidator());
	}

	public DcrMcpOAuth2ClientManager(McpClientRegistrationRepository repository,
			DynamicClientRegistrationService clientRegistrationService, McpMetadataDiscoveryService discovery,
			UrlValidator urlValidator) {
		Assert.notNull(repository, "repository cannot be null");
		Assert.notNull(clientRegistrationService, "clientRegistrationService cannot be null");
		Assert.notNull(discovery, "discovery cannot be null");
		Assert.notNull(urlValidator, "urlValidator cannot be null");
		this.clientRegistrationService = clientRegistrationService;
		this.discovery = discovery;
		this.urlValidator = urlValidator;
		this.repository = repository;
		this.scopeStepUp = new ScopeStepUp(repository);
	}

	/**
	 * Register an OAuth2 client for the given MCP server just in time, on a {@code 401}
	 * response.
	 * <p>
	 * The registration request is an {@code authorization_code} request, see
	 * {@link DynamicClientRegistrationRequest#authorizationCode(String)}, with the
	 * redirect URI {@code {baseUrl}/authorize/oauth2/code/{registrationId}}. Change it
	 * with {@link #setRegistrationRequestCustomizer(Customizer)}.
	 *
	 * @see <a href=
	 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#dynamic-client-registration">Dynamic
	 * client registration</a>
	 */
	@Override
	public void registerClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException, DcrNotSupportedException {
		Assert.hasText(wwwAuthenticateHeader, "wwwAuthenticateHeader cannot be empty");
		log.debug("Registering MCP client [{}] for server [{}] from WWW-Authenticate header", registrationId,
				mcpServerUrl);
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(baseUrl, "baseUrl cannot be empty");
		doRegisterClient(registrationId, mcpServerUrl, registrationRequest(registrationId, baseUrl),
				WwwAuthenticateParameters.parse(wwwAuthenticateHeader));
	}

	/**
	 * Register an OAuth2 client for the given MCP server ahead of time, before calling
	 * the MCP server. The authorization server is discovered by calling the MCP server's
	 * resource metadata endpoint.
	 * <p>
	 * The registration request is sent as given: the customizer set with
	 * {@link #setRegistrationRequestCustomizer(Customizer)} is not applied. When the
	 * request has no scopes, they are discovered from the MCP server. The
	 * {@code offline_access} scope may be added when the request has the
	 * {@code refresh_token} grant and the authorization server supports it.
	 * @param registrationId the unique identifier for this client registration
	 * @param mcpServerUrl the URL of the MCP server
	 * @param registrationRequest the Dynamic Client Registration request, for example
	 * {@link DynamicClientRegistrationRequest#authorizationCode(String)}
	 * @throws ClientAlreadyExistsException when a client with this registration ID exists
	 * already
	 * @throws DcrNotSupportedException when the authorization server does not support
	 * Dynamic Client Registration
	 */
	public void registerClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest)
			throws ClientAlreadyExistsException, DcrNotSupportedException {
		Assert.notNull(registrationRequest, "registrationRequest cannot be null");
		log.debug("Registering MCP client [{}] for server [{}] via metadata discovery", registrationId, mcpServerUrl);
		doRegisterClient(registrationId, mcpServerUrl, registrationRequest, null);
	}

	@Override
	public boolean updateScopes(String registrationId, String wwwAuthenticateHeader) {
		return scopeStepUp.updateOAuth2ClientScopes(registrationId, wwwAuthenticateHeader);
	}

	/**
	 * Customize the Dynamic Client Registration request built by
	 * {@link #registerClient(String, String, String, String)}, before it is sent. Scopes
	 * set here take precedence over the scopes discovered from the MCP server. It does
	 * not apply to
	 * {@link #registerClient(String, String, DynamicClientRegistrationRequest)}.
	 * @param registrationRequestCustomizer the customizer of the request
	 */
	public void setRegistrationRequestCustomizer(
			Customizer<DynamicClientRegistrationRequest.Builder> registrationRequestCustomizer) {
		Assert.notNull(registrationRequestCustomizer, "registrationRequestCustomizer cannot be null");
		this.registrationRequestCustomizer = registrationRequestCustomizer;
	}

	/**
	 * Customize the {@link ClientRegistration} built from the Dynamic Client Registration
	 * response, before it is saved.
	 * @param clientRegistrationCustomizer the customizer of the client registration
	 */
	public void setClientRegistrationCustomizer(Customizer<ClientRegistration.Builder> clientRegistrationCustomizer) {
		Assert.notNull(clientRegistrationCustomizer, "clientRegistrationCustomizer cannot be null");
		this.clientRegistrationCustomizer = clientRegistrationCustomizer;
	}

	private void doRegisterClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest,
			@Nullable WwwAuthenticateParameters wwwAuthenticateParameters)
			throws ClientAlreadyExistsException, DcrNotSupportedException {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(mcpServerUrl, "mcpServerUrl cannot be empty");
		if (this.repository.findByRegistrationId(registrationId) != null) {
			log.debug("Client registration [{}] already exists", registrationId);
			throw new ClientAlreadyExistsException(registrationId);
		}
		if (wwwAuthenticateParameters == null) {
			wwwAuthenticateParameters = this.discovery.getWwwAuthenticateParameters(mcpServerUrl);
		}
		var mcpMetadata = this.discovery.getMcpMetadata(mcpServerUrl, wwwAuthenticateParameters);
		Assert.notNull(mcpMetadata.protectedResourceMetadata().authorizationServers(),
				"cannot find authorization_servers from MCP Server's protected resource metadata");
		var issuerUrl = mcpMetadata.protectedResourceMetadata().authorizationServers().get(0);
		log.debug("Discovered authorization server [{}] for registration [{}]", issuerUrl, registrationId);
		var autoconfiguredRegistration = discoverIssuerConfiguration(issuerUrl);
		var authServerMetadata = autoconfiguredRegistration.getProviderDetails().getConfigurationMetadata();
		registrationRequest = updateScopes(registrationRequest, mcpMetadata, authServerMetadata);

		log.debug("Performing dynamic client registration at [{}] for registration [{}]", issuerUrl, registrationId);
		var registrationResponse = this.clientRegistrationService.register(registrationRequest, issuerUrl);
		log.debug("Dynamic client registration successful for registration [{}], clientId=[{}]", registrationId,
				registrationResponse.clientId());
		var clientRegistrationBuilder = toClientRegistration(registrationId, registrationRequest, registrationResponse,
				autoconfiguredRegistration);
		this.clientRegistrationCustomizer.customize(clientRegistrationBuilder);
		var clientRegistration = clientRegistrationBuilder.build();
		validateClientRegistration(clientRegistration);
		this.repository.save(clientRegistration, mcpMetadata.protectedResourceMetadata().resource());
	}

	/**
	 * Select scopes, in order of preference: from the original request, from the
	 * {@code WWW-Authenticate} header, from the Protected Resource Metadata. When scopes
	 * are found, {@code offline_access} may be added, see
	 * {@link #addOfflineAccess(DynamicClientRegistrationRequest, Map)}.
	 */
	private DynamicClientRegistrationRequest updateScopes(DynamicClientRegistrationRequest originalRequest,
			McpMetadata mcpMetadata, Map<String, Object> authorizationServerMetadata) {
		String scopes = null;
		if (StringUtils.hasText(originalRequest.getScope())) {
			scopes = originalRequest.getScope();
		}
		else if (mcpMetadata.wwwAuthenticateParameters() != null
				&& StringUtils.hasText(mcpMetadata.wwwAuthenticateParameters().getScope())) {
			scopes = mcpMetadata.wwwAuthenticateParameters().getScope();
		}
		else if (!CollectionUtils.isEmpty(mcpMetadata.protectedResourceMetadata().scopesSupported())) {
			scopes = String.join(" ", mcpMetadata.protectedResourceMetadata().scopesSupported());
		}

		if (scopes == null) {
			// "no scopes" implies requesting "default scopes": don't add offline_access
			return originalRequest;
		}
		scopes = addOfflineAccess(scopes, originalRequest.getGrantTypes(), authorizationServerMetadata);
		return DynamicClientRegistrationRequest.from(originalRequest).scope(scopes).build();
	}

	/**
	 * Add the {@code offline_access} scope when the client requests the
	 * {@code refresh_token} grant and the authorization server lists
	 * {@code offline_access}. This also applies to scopes set explicitly on the request.
	 */
	private static String addOfflineAccess(String scopes, List<String> grantTypes,
			Map<String, Object> authorizationServerMetadata) {
		// offline_access is only useful to obtain refresh tokens; the request builder
		// ensures refresh_token is only used alongside authorization_code
		if (!grantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
			return scopes;
		}

		Set<String> requestedScopes = new HashSet<>(Arrays.asList(scopes.split(" ")));
		if (requestedScopes.contains(OfflineAccess.OFFLINE_ACCESS)
				|| !OfflineAccess.isSupported(authorizationServerMetadata)) {
			return scopes;
		}

		requestedScopes.add(OfflineAccess.OFFLINE_ACCESS);
		log.debug("Authorization server supports offline_access, requesting scopes {}", requestedScopes);
		return String.join(" ", requestedScopes);
	}

	private DynamicClientRegistrationRequest registrationRequest(String registrationId, String baseUrl) {
		var redirectUri = DEFAULT_REDIRECT_URI_TEMPLATE.replace("{baseUrl}", baseUrl)
			.replace("{registrationId}", registrationId);
		var builder = DynamicClientRegistrationRequest.builder()
			.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN))
			.redirectUris(List.of(redirectUri));
		this.registrationRequestCustomizer.customize(builder);
		return builder.build();
	}

	private static ClientRegistration.Builder toClientRegistration(String registrationId,
			DynamicClientRegistrationRequest registrationRequest,
			DynamicClientRegistrationResponse registrationResponse, ClientRegistration originalRegistration) {
		ClientRegistration.Builder registrationBuilder = ClientRegistration.withClientRegistration(originalRegistration)
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

		List<String> grantTypes = (registrationResponse.grantTypes() != null
				&& !registrationResponse.grantTypes().isEmpty()) ? registrationResponse.grantTypes()
						: registrationRequest.getGrantTypes();
		registrationBuilder.authorizationGrantType(selectGrantType(grantTypes));

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

		return registrationBuilder;
	}

	private static final List<AuthorizationGrantType> GRANT_TYPE_PREFERENCE = List.of(
			AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.DEVICE_CODE,
			AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.JWT_BEARER);

	/**
	 * Pick the grant type for the {@link ClientRegistration}, in order of preference:
	 * {@code authorization_code}, {@code device_code}, {@code client_credentials},
	 * {@code jwt-bearer}. Defaults to {@code client_credentials}.
	 */
	private static AuthorizationGrantType selectGrantType(@Nullable List<String> grantTypes) {
		if (grantTypes != null) {
			for (var candidate : GRANT_TYPE_PREFERENCE) {
				if (grantTypes.contains(candidate.getValue())) {
					return candidate;
				}
			}
			if (!grantTypes.isEmpty()) {
				return new AuthorizationGrantType(grantTypes.get(0));
			}
		}
		return AuthorizationGrantType.CLIENT_CREDENTIALS;
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
					throw new IllegalStateException(
							String.format("Invalid %s [value=%s]: %s", uri, url, e.getMessage()), e);
				}
			}
		}
	}

	/**
	 * Gather metadata configuration from the issuer. Spring Security pre-fills a
	 * {@link ClientRegistration} with the information, which can be reused for the final
	 * client registration stored in the app's repository.
	 */
	private ClientRegistration discoverIssuerConfiguration(String issuerUrl) {
		try {
			urlValidator.validateUrl(issuerUrl);
		}
		catch (InvalidUrlException e) {
			throw new IllegalStateException(
					String.format("Invalid authorization server url [value=%s]: %s", issuerUrl, e.getMessage()), e);
		}

		return ClientRegistrations.fromIssuerLocation(issuerUrl).clientId("~~~~~ignored~~~~~").build();
	}

}
