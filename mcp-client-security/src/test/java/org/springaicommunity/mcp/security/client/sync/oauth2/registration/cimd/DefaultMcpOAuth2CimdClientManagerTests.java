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

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.ProtectedResourceMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class DefaultMcpOAuth2CimdClientManagerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com";

	private static final String ISSUER_URL = "https://auth.example.com";

	private static final String RESOURCE_ID = "https://mcp.example.com";

	private static final String BASE_URL = "https://app.example.com";

	private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

	private static final ClientRegistration CLIENT_REGISTRATION = ClientRegistration.withRegistrationId(REGISTRATION_ID)
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.clientId("existing-client-id")
		.tokenUri(ISSUER_URL + "/oauth2/token")
		.authorizationUri(ISSUER_URL + "/oauth2/authorize")
		.redirectUri("https://app.example.com/callback")
		.build();

	private static MockedStatic<ClientRegistrations> clientRegistrationsMock;

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final McpMetadataDiscoveryService discovery = mock(McpMetadataDiscoveryService.class);

	private final UrlValidator urlValidator = mock(UrlValidator.class);

	private final DefaultMcpOAuth2CimdClientManager manager = new DefaultMcpOAuth2CimdClientManager(this.discovery,
			this.repository, this.urlValidator);

	@BeforeAll
	static void beforeAll() {
		DefaultMcpOAuth2CimdClientManagerTests.clientRegistrationsMock = mockStatic(ClientRegistrations.class);
		clientRegistrationsMock.when(() -> ClientRegistrations.fromIssuerLocation(ISSUER_URL))
			.thenReturn(ClientRegistration.withRegistrationId("placeholder")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientId("placeholder")
				.tokenUri(ISSUER_URL + "/oauth2/token")
				.authorizationUri(ISSUER_URL + "/oauth2/authorize")
				.providerConfigurationMetadata(Map.of("token_endpoint", ISSUER_URL + "/oauth2/token",
						"authorization_endpoint", ISSUER_URL + "/oauth2/authorize")));
	}

	@AfterAll
	static void afterAll() {
		DefaultMcpOAuth2CimdClientManagerTests.clientRegistrationsMock.close();
	}

	@Nested
	class CreateClient {

		@Test
		void throwsWhenRegistrationAlreadyExists() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);

			assertThatThrownBy(
					() -> manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(ClientAlreadyExistsException.class)
				.hasMessageContaining(REGISTRATION_ID);

			verifyNoInteractions(discovery);
		}

		@Test
		void createClientSuccessfully() throws ClientAlreadyExistsException {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

			var savedRegistration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(savedRegistration).isNotNull();
			assertThat(savedRegistration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
			assertThat(savedRegistration.getClientId())
				.isEqualTo("https://app.example.com/test-registration/client-id-metadata.json");
			assertThat(savedRegistration.getAuthorizationGrantType())
				.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
			assertThat(savedRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
			assertThat(savedRegistration.getRedirectUri())
				.isEqualTo("https://app.example.com/authorize/oauth2/code/test-registration");
			assertThat(repository.findResourceIdByRegistrationId(REGISTRATION_ID)).isEqualTo(RESOURCE_ID);
		}

		@Test
		void extractsScopesFromWwwAuthenticateHeader() throws ClientAlreadyExistsException {
			String headerWithScopes = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:read mcp:write\"";
			var wwwAuthParams = WwwAuthenticateParameters.parse(headerWithScopes);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:delete"));
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, headerWithScopes, BASE_URL);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:read", "mcp:write");
		}

		@Test
		void extractsScopesFromProtectedResourceMetadata() throws ClientAlreadyExistsException {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL),
					List.of("mcp:tools", "mcp:prompts"));
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:tools", "mcp:prompts");
		}

		@Test
		void throwsWhenConfigurationMetadataContainsInvalidUrl() throws InvalidUrlException {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			var tokenUrl = ISSUER_URL + "/oauth2/token";
			doThrow(new InvalidUrlException("Invalid test url", tokenUrl)).when(urlValidator).validateUrl(tokenUrl);

			assertThatThrownBy(
					() -> manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Invalid token_endpoint [value=%s]: Invalid test url".formatted(tokenUrl));
		}

		@Test
		void throwsWhenAuthorizationServerUrlIsInvalid() throws InvalidUrlException {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			doThrow(new InvalidUrlException("Invalid test url", ISSUER_URL)).when(urlValidator).validateUrl(ISSUER_URL);

			assertThatThrownBy(
					() -> manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Invalid authorization server URL: Invalid test url");

			assertThat(repository.findByRegistrationId(REGISTRATION_ID)).isNull();
		}

		@Test
		void appliesClientRegistrationCustomizer() throws ClientAlreadyExistsException {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			manager.setClientRegistrationCustomizer(
					clientRegistration -> ClientRegistration.withClientRegistration(clientRegistration)
						.clientName("Custom Name")
						.build());

			manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getClientName()).isEqualTo("Custom Name");
		}

		@Test
		void throwsWhenProtectedResourceMetadataHasNoAuthorizationServers() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(WWW_AUTHENTICATE_HEADER);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(), null);
			var mcpMetadata = new McpMetadata(wwwAuthParams, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);

			assertThatThrownBy(
					() -> manager.createClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Protected Resource Metadata must expose at least one authorization server");
		}

	}

	@Nested
	class UpdateClient {

		@BeforeEach
		void setUp() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);
		}

		@Test
		void updateScopes() {
			repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read"));

			boolean result = manager.updateClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read mcp:write\"");

			assertThat(result).isTrue();
			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
		}

	}

}
