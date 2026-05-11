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

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DynamicClientRegistrationService}.
 */
class DynamicClientRegistrationServiceTests {

	@Test
	void registerValidatesAuthServerUrl() throws InvalidUrlException {
		UrlValidator urlValidator = mock(UrlValidator.class);
		doThrow(new InvalidUrlException("Invalid URL", "https://evil.example.com")).when(urlValidator)
			.validateUrl("https://evil.example.com");

		DynamicClientRegistrationService service = new DynamicClientRegistrationService(RestClient.builder().build(),
				urlValidator);
		DynamicClientRegistrationRequest request = DynamicClientRegistrationRequest.builder().build();

		assertThatThrownBy(() -> service.register(request, "https://evil.example.com"))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Invalid authorization server URL: Invalid URL");

		verify(urlValidator).validateUrl("https://evil.example.com");
	}

	@Test
	void registerValidatesRegistrationEndpointUrl() throws InvalidUrlException {
		UrlValidator urlValidator = mock(UrlValidator.class);
		doThrow(new InvalidUrlException("Invalid URL", "http://bad-endpoint.example.com")).when(urlValidator)
			.validateUrl("http://bad-endpoint.example.com");

		DynamicClientRegistrationService service = new DynamicClientRegistrationService(RestClient.builder().build(),
				urlValidator);
		DynamicClientRegistrationRequest request = DynamicClientRegistrationRequest.builder().build();

		try (MockedStatic<ClientRegistrations> clientRegistrationsMock = mockStatic(ClientRegistrations.class)) {
			clientRegistrationsMock
				.when(() -> ClientRegistrations.fromIssuerLocation("https://good-auth-server.example.com"))
				.thenReturn(ClientRegistration.withRegistrationId("placeholder")
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.clientId("placeholder")
					.tokenUri("https://good-auth-server.example.com/oauth2/token")
					.providerConfigurationMetadata(Map.of("registration_endpoint", "http://bad-endpoint.example.com")));

			assertThatThrownBy(() -> service.register(request, "https://good-auth-server.example.com"))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Invalid registration_endpoint URL: Invalid URL");
		}

		verify(urlValidator).validateUrl("https://good-auth-server.example.com");
		verify(urlValidator).validateUrl("http://bad-endpoint.example.com");
	}

}
