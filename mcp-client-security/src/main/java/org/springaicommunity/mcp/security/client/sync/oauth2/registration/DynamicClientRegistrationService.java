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

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.client.RestClient;

/**
 * Service to perform OAuth2 Dynamic Client Registration. It expects an open registration
 * endpoint, with no authentication.
 * <p>
 * Uses a RestClient internally to perform HTTP requests. By default, uses a new rest
 * client with a Jackson JSON mapper.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC7591 - OAuth 2.0
 * Dynamic Client Registration Protocol</a>
 */
public class DynamicClientRegistrationService {

	private final RestClient restClient;

	private final UrlValidator urlValidator;

	private static final Logger log = LoggerFactory.getLogger(DynamicClientRegistrationService.class);

	private final ClaimConversionService claimConversionService = ClaimConversionService.getSharedInstance();

	private static final String GRANT_TYPES = "grant_types";

	private static final String REDIRECT_URIS = "redirect_uris";

	private static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";

	private static final String RESPONSE_TYPES = "response_types";

	private static final String CLIENT_NAME = "client_name";

	private static final String JWKS_URI = "jwks_uri";

	private static final String CLIENT_URI = "client_uri";

	private static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";

	private static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";

	public DynamicClientRegistrationService() {
		this(new DefaultUrlValidator());
	}

	public DynamicClientRegistrationService(UrlValidator validator) {
		this(RestClient.create(), validator);
	}

	public DynamicClientRegistrationService(RestClient restClient, UrlValidator urlValidator) {
		this.restClient = restClient;
		this.urlValidator = urlValidator;
	}

	public DynamicClientRegistrationResponse register(DynamicClientRegistrationRequest registrationRequest,
			String authServerUrl) {
		var registrationEndpoint = findRegistrationEndpoint(authServerUrl);
		try {
			urlValidator.validateUrl(registrationEndpoint);
		}
		catch (InvalidUrlException e) {
			throw new IllegalStateException("Invalid registration_endpoint URL: " + e.getMessage(), e);
		}
		log.debug("Performing dynamic client registration at [{}]", registrationEndpoint);
		var typeRef = new ParameterizedTypeReference<Map<String, Object>>() {
		};
		var response = restClient.post()
			.uri(registrationEndpoint)
			.contentType(MediaType.APPLICATION_JSON)
			.body(createRegistrationRequest(registrationRequest))
			.retrieve()
			.body(typeRef);
		if (response == null) {
			throw new IllegalStateException("Cannot register client");
		}
		var clientId = response.get(OAuth2ParameterNames.CLIENT_ID) != null
				? response.get(OAuth2ParameterNames.CLIENT_ID).toString() : null;
		if (clientId == null) {
			throw new IllegalStateException("client_id is required in registration response");
		}
		//@formatter:off
		var registrationResponse = new DynamicClientRegistrationResponse(
				clientId,
				extract(response, OAuth2ParameterNames.CLIENT_SECRET, String.class),
				extract(response, CLIENT_ID_ISSUED_AT, Instant.class),
				extract(response, CLIENT_SECRET_EXPIRES_AT, Instant.class),
				extract(response, REDIRECT_URIS, List.class),
				extract(response, TOKEN_ENDPOINT_AUTH_METHOD, String.class),
				extract(response, GRANT_TYPES, List.class),
				extract(response, RESPONSE_TYPES, List.class),
				extract(response, CLIENT_NAME, String.class),
				extract(response, OAuth2ParameterNames.SCOPE, String.class),
				extract(response, JWKS_URI, String.class)
		);
		//@formatter:on

		log.debug("Dynamic client registration successful, client ID: [{}]", registrationResponse.clientId());
		return registrationResponse;
	}

	private @Nullable <T> T extract(Map<String, Object> response, String client_id_issued_at, Class<T> target) {
		return response.get(client_id_issued_at) != null
				? claimConversionService.convert(response.get(client_id_issued_at), target) : null;
	}

	private Map<String, Object> createRegistrationRequest(DynamicClientRegistrationRequest request) {
		Map<String, Object> parameters = new HashMap<>();
		if (request.getGrantTypes() != null) {
			parameters.put(GRANT_TYPES, request.getGrantTypes());
		}
		if (request.getRedirectUris() != null) {
			parameters.put(REDIRECT_URIS, request.getRedirectUris());
		}
		if (request.getTokenEndpointAuthMethod() != null) {
			parameters.put(TOKEN_ENDPOINT_AUTH_METHOD, request.getTokenEndpointAuthMethod());
		}
		if (request.getResponseTypes() != null) {
			parameters.put(RESPONSE_TYPES, request.getResponseTypes());
		}
		if (request.getClientName() != null) {
			parameters.put(CLIENT_NAME, request.getClientName());
		}
		if (request.getClientUri() != null) {
			parameters.put(CLIENT_URI, request.getClientUri());
		}
		if (request.getScope() != null) {
			parameters.put(OAuth2ParameterNames.SCOPE, request.getScope());
		}
		return parameters;
	}

	private String findRegistrationEndpoint(String authServerUrl) {
		try {
			urlValidator.validateUrl(authServerUrl);
		}
		catch (InvalidUrlException e) {
			throw new IllegalStateException("Invalid authorization server URL: " + e.getMessage(), e);
		}
		log.debug("Discovering registration endpoint for auth server [{}]", authServerUrl);
		var builder = ClientRegistrations.fromIssuerLocation(authServerUrl).clientId("~~~~ignored~~~~").build();
		var registrationEndpoint = builder.getProviderDetails().getConfigurationMetadata().get("registration_endpoint");
		if (registrationEndpoint == null) {
			throw new IllegalStateException(
					"No registration endpoint found for auth server [%s]".formatted(authServerUrl));
		}
		log.debug("Found registration endpoint [{}]", registrationEndpoint);
		return registrationEndpoint.toString();
	}

}
