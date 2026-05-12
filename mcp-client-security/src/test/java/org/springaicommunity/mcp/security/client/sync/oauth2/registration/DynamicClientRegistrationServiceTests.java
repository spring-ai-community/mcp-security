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

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
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

	@Test
	void convertHttpResponse() {
		var rcBuilder = RestClient.builder();
		var mockServer = MockRestServiceServer.bindTo(rcBuilder).build();
		var client = rcBuilder.build();
		var sampleResponse = """
				{
					"client_id": "client-123",
					"client_secret": "secret-456",
					"client_id_issued_at": 1715525000,
					"client_secret_expires_at": 1715535000,
					"redirect_uris": ["https://client.example.org/callback"],
					"token_endpoint_auth_method": "client_secret_basic",
					"grant_types": ["authorization_code", "client_credentials"],
					"response_types": ["code"],
					"client_name": "Test Client",
					"scope": "read write",
					"jwks_uri": "https://client.example.org/jwks.json"
				}
				""";

		mockServer.expect(MockRestRequestMatchers.requestTo("http://registration-endpoint.example.com"))
			.andRespond(MockRestResponseCreators.withSuccess(sampleResponse, MediaType.APPLICATION_JSON));

		var service = new DynamicClientRegistrationService(client, url -> {
		});

		try (MockedStatic<ClientRegistrations> clientRegistrationsMock = mockStatic(ClientRegistrations.class)) {
			clientRegistrationsMock
				.when(() -> ClientRegistrations.fromIssuerLocation("https://good-auth-server.example.com"))
				.thenReturn(ClientRegistration.withRegistrationId("placeholder")
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.clientId("placeholder")
					.tokenUri("https://good-auth-server.example.com/oauth2/token")
					.providerConfigurationMetadata(
							Map.of("registration_endpoint", "http://registration-endpoint.example.com")));

			var request = DynamicClientRegistrationRequest.builder().build();
			var response = service.register(request, "https://good-auth-server.example.com");

			assertThat(response.clientId()).isEqualTo("client-123");
			assertThat(response.clientSecret()).isEqualTo("secret-456");
			assertThat(response.redirectUris()).containsExactly("https://client.example.org/callback");
			assertThat(response.tokenEndpointAuthMethod()).isEqualTo("client_secret_basic");
			assertThat(response.grantTypes()).containsExactly("authorization_code", "client_credentials");
			assertThat(response.responseTypes()).containsExactly("code");
			assertThat(response.clientName()).isEqualTo("Test Client");
			assertThat(response.scope()).isEqualTo("read write");
			assertThat(response.jwksUri()).isEqualTo("https://client.example.org/jwks.json");
		}
	}

}
