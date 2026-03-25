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

import java.util.List;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.ProtectedResourceMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class DefaultMcpOAuth2ClientManagerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com";

	private static final String ISSUER_URL = "https://auth.example.com";

	private static final ClientRegistration CLIENT_REGISTRATION = ClientRegistration.withRegistrationId(REGISTRATION_ID)
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
		.clientId("existing-client-id")
		.tokenUri(ISSUER_URL + "/oauth2/token")
		.build();

	private static final String RESOURCE_ID = "https://mcp.example.com";

	private static final String DCR_RESPONSE = "{\"client_id\": \"client-id-123\"}\n";

	private static MockedStatic<ClientRegistrations> clientRegistrationsMock;

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final DynamicClientRegistrationService clientRegistrationService = mock(
			DynamicClientRegistrationService.class);

	private final McpMetadataDiscoveryService discovery = mock(McpMetadataDiscoveryService.class);

	private final DefaultMcpOAuth2ClientManager manager = new DefaultMcpOAuth2ClientManager(this.repository,
			this.clientRegistrationService, this.discovery);

	@BeforeAll
	static void beforeAll() {
		DefaultMcpOAuth2ClientManagerTests.clientRegistrationsMock = mockStatic(ClientRegistrations.class);
		clientRegistrationsMock.when(() -> ClientRegistrations.fromIssuerLocation(ISSUER_URL))
			.thenReturn(ClientRegistration.withRegistrationId("placeholder")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId("placeholder")
				.tokenUri(ISSUER_URL + "/oauth2/token")
				.authorizationUri(ISSUER_URL + "/oauth2/authorize"));

	}

	@AfterAll
	static void afterAll() {
		DefaultMcpOAuth2ClientManagerTests.clientRegistrationsMock.close();
	}

	@Nested
	class RegisterMcpClientWithDiscovery {

		@Test
		void skipsWhenRegistrationAlreadyExists() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);
			var request = DynamicClientRegistrationRequest.builder().build();

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			verifyNoInteractions(discovery);
			verifyNoInteractions(clientRegistrationService);
		}

		@Test
		void register() {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var dcrResponse = """
					{
						"client_id": "client-id-123",
						"client_secret": "client-secret",
						"grant_types": ["client_credentials"],
						"client_name": "Test Client"
					}
					""";
			configureMocks(wwwAuthParams, prm, dcrResponse);

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					DynamicClientRegistrationRequest.builder().build());

			var savedRegistration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(savedRegistration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
			assertThat(savedRegistration.getClientId()).isEqualTo("client-id-123");
			assertThat(savedRegistration.getClientSecret()).isEqualTo("client-secret");
			assertThat(savedRegistration.getClientName()).isEqualTo("Test Client");
			assertThat(repository.findResourceIdByRegistrationId(REGISTRATION_ID)).isEqualTo(RESOURCE_ID);
		}

		@Test
		@DisplayName("Registers scopes from WWW-Authenticate header when present")
		void registerScopesFromWwwAuthenticateHeader() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:read mcp:write\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:delete"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					DynamicClientRegistrationRequest.builder().build());

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration.getScopes()).containsExactly("mcp:read", "mcp:write");
		}

		@Test
		@DisplayName("Registers scopes from Protected Resource Metadata when absent from WWW-Authenticate header")
		void registerScopesFromProtectedResourceMetadata() {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL),
					List.of("mcp:tools", "mcp:prompts"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					DynamicClientRegistrationRequest.builder().build());

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration.getScopes()).containsExactly("mcp:tools", "mcp:prompts");
		}

		@Test
		void preservesRequestScopesWhenAlreadySet() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:admin\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:tools"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var request = DynamicClientRegistrationRequest.builder().scope("mcp:custom").build();

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration.getScopes()).containsExactly("mcp:custom");
		}

		private void configureMocks(@Nullable WwwAuthenticateParameters wwwAuthParams,
				ProtectedResourceMetadata protectedResourceMetadata, String dcrResponse) {
			when(DefaultMcpOAuth2ClientManagerTests.this.discovery.getWwwAuthenticateParameters(MCP_SERVER_URL))
				.thenReturn(wwwAuthParams);
			var mcpMetadata = new McpMetadata(wwwAuthParams, protectedResourceMetadata);
			when(DefaultMcpOAuth2ClientManagerTests.this.discovery.getMcpMetadata(MCP_SERVER_URL, wwwAuthParams))
				.thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			when(DefaultMcpOAuth2ClientManagerTests.this.clientRegistrationService.register(any(), eq(ISSUER_URL)))
				.thenReturn(registrationResponse);
		}

	}

	@Nested
	class RegisterMcpClientWithWwwAuthenticateHeader {

		private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

		@Test
		void skipsWhenRegistrationAlreadyExists() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);
			var request = DynamicClientRegistrationRequest.builder().build();

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					WWW_AUTHENTICATE_HEADER, request);

			verifyNoInteractions(DefaultMcpOAuth2ClientManagerTests.this.discovery);
			verifyNoInteractions(DefaultMcpOAuth2ClientManagerTests.this.clientRegistrationService);
		}

		@Test
		void parsesHeaderAndRegistersClient() {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(null, prm);
			when(DefaultMcpOAuth2ClientManagerTests.this.discovery.getMcpMetadata(eq(MCP_SERVER_URL), any()))
				.thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse("""
					{
						"client_id": "dynamic-client-id",
						"client_secret": "dynamic-secret",
						"redirect_uris": ["https://redirect.example.com/callback"],
						"token_endpoint_auth_method": "client_secret_post",
						"grant_types": ["authorization_code"],
						"response_types": ["code"],
						"client_name": "MCP Client",
						"scope": "openid profile"
					}
					""");
			when(DefaultMcpOAuth2ClientManagerTests.this.clientRegistrationService.register(any(), eq(ISSUER_URL)))
				.thenReturn(registrationResponse);

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					WWW_AUTHENTICATE_HEADER, DynamicClientRegistrationRequest.builder().build());

			verify(DefaultMcpOAuth2ClientManagerTests.this.discovery, never()).getWwwAuthenticateParameters(any());
			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
			assertThat(registration.getClientId()).isEqualTo("dynamic-client-id");
			assertThat(registration.getClientSecret()).isEqualTo("dynamic-secret");
			assertThat(registration.getClientAuthenticationMethod())
				.isEqualTo(new ClientAuthenticationMethod("client_secret_post"));
			assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
			assertThat(registration.getRedirectUri()).isEqualTo("https://redirect.example.com/callback");
			assertThat(registration.getScopes()).containsExactlyInAnyOrder("openid", "profile");
			assertThat(registration.getClientName()).isEqualTo("MCP Client");
		}

	}

	@Nested
	class UpdateMcpClient {

		@Test
		void returnsFalseWhenErrorIsNotInsufficientScope() {
			boolean result = DefaultMcpOAuth2ClientManagerTests.this.manager.updateMcpClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"invalid_token\", scope=\"mcp:read\"");

			assertThat(result).isFalse();
		}

		@Test
		void returnsFalseWhenNoScope() {
			boolean result = DefaultMcpOAuth2ClientManagerTests.this.manager.updateMcpClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\"");

			assertThat(result).isFalse();
		}

		@Test
		void returnsFalseWhenScopesAlreadyPresent() {
			var existingRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId("client-id")
				.tokenUri(ISSUER_URL + "/oauth2/token")
				.scope("mcp:read", "mcp:write")
				.build();
			repository.addClientRegistration(existingRegistration, RESOURCE_ID);

			boolean result = DefaultMcpOAuth2ClientManagerTests.this.manager.updateMcpClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read\"");

			assertThat(result).isFalse();
		}

		@Test
		void updatesScopesWhenInsufficientScopeError() {
			var existingRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId("client-id")
				.tokenUri(ISSUER_URL + "/oauth2/token")
				.scope("mcp:read")
				.build();
			repository.addClientRegistration(existingRegistration, RESOURCE_ID);

			boolean result = DefaultMcpOAuth2ClientManagerTests.this.manager.updateMcpClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read mcp:write\"");

			assertThat(result).isTrue();
			var updatedRegistration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(updatedRegistration).isNotNull();
			assertThat(updatedRegistration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
		}

	}

	@Nested
	class ToClientRegistration {

		@Test
		void usesResponseValuesOverRequestValues() {
			configureMocks("""
					{
						"client_id": "response-client-id",
						"client_secret": "response-secret",
						"redirect_uris": ["https://response.example.com/callback"],
						"token_endpoint_auth_method": "client_secret_post",
						"grant_types": ["authorization_code"],
						"client_name": "Response Client Name",
						"scope": "response:scope"
					}
					""");
			var request = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
				.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientName("Request Client Name")
				.scope("request:scope")
				.build();

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
					request);

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getClientId()).isEqualTo("response-client-id");
			assertThat(saved.getClientSecret()).isEqualTo("response-secret");
			assertThat(saved.getClientAuthenticationMethod())
				.isEqualTo(new ClientAuthenticationMethod("client_secret_post"));
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
			assertThat(saved.getRedirectUri()).isEqualTo("https://response.example.com/callback");
			assertThat(saved.getScopes()).containsExactly("response:scope");
			assertThat(saved.getClientName()).isEqualTo("Response Client Name");
		}

		@Test
		void fallsBackToRequestValuesWhenResponseValuesAreNull() {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(DCR_RESPONSE);

			var request = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
				.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.redirectUris(List.of("https://request.example.com/callback"))
				.clientName("Request Client Name")
				.scope("request:scope")
				.build();

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
					request);

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
			assertThat(saved.getRedirectUri()).isEqualTo("https://request.example.com/callback");
			assertThat(saved.getScopes()).containsExactly("request:scope");
			assertThat(saved.getClientName()).isEqualTo("Request Client Name");
		}

		@Test
		void defaultsToClientCredentialsWhenNoGrantTypes() {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(DCR_RESPONSE);

			DefaultMcpOAuth2ClientManagerTests.this.manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
					DynamicClientRegistrationRequest.builder().build());

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		}

		private void configureMocks(String dcrResponse) {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(null, prm);
			when(DefaultMcpOAuth2ClientManagerTests.this.discovery.getMcpMetadata(eq(MCP_SERVER_URL), any()))
				.thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			when(DefaultMcpOAuth2ClientManagerTests.this.clientRegistrationService.register(any(), eq(ISSUER_URL)))
				.thenReturn(registrationResponse);
		}

	}

	private static DynamicClientRegistrationResponse dcrResponse(String json) {
		return JsonMapper.builder()
			.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
			.build()
			.readValue(json, DynamicClientRegistrationResponse.class);
	}

}
