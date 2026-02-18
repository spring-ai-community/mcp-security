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

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
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

	public DynamicClientRegistrationService() {
		this.restClient = RestClient.builder()
			.configureMessageConverters((converters) -> converters.registerDefaults()
				.withJsonConverter(new JacksonJsonHttpMessageConverter(JsonMapper.builder()
					.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
					.changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_NULL)))))
			.build();
	}

	public DynamicClientRegistrationService(RestClient restClient) {
		this.restClient = restClient;
	}

	public DynamicClientRegistrationResponse register(DynamicClientRegistrationRequest registrationRequest,
			String authServerUrl) {
		var registrationEndpoint = findRegistrationEndpoint(authServerUrl);
		var registrationResponse = restClient.post()
			.uri(registrationEndpoint)
			.contentType(MediaType.APPLICATION_JSON)
			.body(registrationRequest)
			.retrieve()
			.body(DynamicClientRegistrationResponse.class);
		if (registrationResponse == null) {
			throw new IllegalStateException("Cannot register client");
		}
		return registrationResponse;
	}

	private String findRegistrationEndpoint(String authServerUrl) {
		var builder = ClientRegistrations.fromIssuerLocation(authServerUrl).clientId("~~~~ignored~~~~").build();
		var registrationEndpoint = builder.getProviderDetails().getConfigurationMetadata().get("registration_endpoint");
		if (registrationEndpoint == null) {
			throw new IllegalStateException(
					"No registration endpoint found for auth server [%s]".formatted(authServerUrl));
		}
		return registrationEndpoint.toString();
	}

}
