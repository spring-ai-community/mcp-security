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
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.ProtectedResourceMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class DefaultMcpOAuth2DcrClientManagerTests {

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

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final DynamicClientRegistrationService clientRegistrationService = mock(
			DynamicClientRegistrationService.class);

	private final McpMetadataDiscoveryService discovery = mock(McpMetadataDiscoveryService.class);

	private final UrlValidator urlValidator = mock(UrlValidator.class);

	private final DefaultMcpOAuth2DcrClientManager manager = new DefaultMcpOAuth2DcrClientManager(this.repository,
			this.clientRegistrationService, this.discovery, this.urlValidator);

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
			assertThat(savedRegistration).isNotNull();
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
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).isNotNull().containsExactly("mcp:read", "mcp:write");
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
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:tools", "mcp:prompts");
		}

		@Test
		@DisplayName("Registers scopes from user request")
		void preservesRequestScopesWhenAlreadySet() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:admin\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:tools"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var request = DynamicClientRegistrationRequest.builder().scope("mcp:custom").build();

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:custom");
		}

		@Test
		@DisplayName("Requests offline access when enabled and supported by the authorization server")
		void requestsOfflineAccessWhenEnabledAndSupported() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:read\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var manager = new DefaultMcpOAuth2DcrClientManager(repository, clientRegistrationService, discovery,
					urlValidator, true);
			var request = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE))
				.redirectUris(List.of("https://client.example.com/callback"))
				.build();

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			var requestCaptor = ArgumentCaptor.forClass(DynamicClientRegistrationRequest.class);
			verify(clientRegistrationService).register(requestCaptor.capture(), any(ClientRegistration.class));
			verify(clientRegistrationService).getAuthorizationServerMetadata(ISSUER_URL);
			assertThat(requestCaptor.getValue().getGrantTypes()).containsExactly("authorization_code", "refresh_token");
			assertThat(requestCaptor.getValue().getScope()).isEqualTo("mcp:read offline_access");
			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:read", "offline_access");
		}

		@Test
		@DisplayName("Does not request offline access when unsupported by the authorization server")
		void doesNotRequestOfflineAccessWhenUnsupported() {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:read\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			when(clientRegistrationService.getAuthorizationServerMetadata(ISSUER_URL))
				.thenReturn(authorizationServerMetadata(List.of("mcp:read")));
			var manager = new DefaultMcpOAuth2DcrClientManager(repository, clientRegistrationService, discovery,
					urlValidator, true);
			var request = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE))
				.redirectUris(List.of("https://client.example.com/callback"))
				.build();

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			var requestCaptor = ArgumentCaptor.forClass(DynamicClientRegistrationRequest.class);
			verify(clientRegistrationService).register(requestCaptor.capture(), any(ClientRegistration.class));
			assertThat(requestCaptor.getValue().getGrantTypes()).containsExactly("authorization_code");
			assertThat(requestCaptor.getValue().getScope()).isEqualTo("mcp:read");
		}

		@Test
		@DisplayName("Throws when configuration metadata contains invalid URL")
		void throwsWhenConfigurationMetadataContainsInvalidUrl() throws InvalidUrlException {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var tokenUrl = ISSUER_URL + "/oauth2/token";
			doThrow(new InvalidUrlException("Invalid test url", tokenUrl)).when(urlValidator).validateUrl(tokenUrl);

			assertThatThrownBy(() -> manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					DynamicClientRegistrationRequest.builder().build()))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Invalid token_endpoint [value=%s]: Invalid test url".formatted(tokenUrl));
		}

		private void configureMocks(@Nullable WwwAuthenticateParameters wwwAuthParams,
				ProtectedResourceMetadata protectedResourceMetadata, String dcrResponse) {
			when(discovery.getWwwAuthenticateParameters(MCP_SERVER_URL)).thenReturn(wwwAuthParams);
			var mcpMetadata = new McpMetadata(wwwAuthParams, protectedResourceMetadata);
			when(discovery.getMcpMetadata(MCP_SERVER_URL, wwwAuthParams)).thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			when(clientRegistrationService.getAuthorizationServerMetadata(ISSUER_URL))
				.thenReturn(authorizationServerMetadata(List.of("mcp:read", "offline_access")));
			when(clientRegistrationService.register(any(), any(ClientRegistration.class)))
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

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, request);

			verifyNoInteractions(discovery);
			verifyNoInteractions(clientRegistrationService);
		}

		@Test
		void register() {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(null, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);
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
			when(clientRegistrationService.getAuthorizationServerMetadata(ISSUER_URL))
				.thenReturn(authorizationServerMetadata(List.of("mcp:read", "offline_access")));
			when(clientRegistrationService.register(any(), any(ClientRegistration.class)))
				.thenReturn(registrationResponse);

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER,
					DynamicClientRegistrationRequest.builder().build());

			verify(discovery, never()).getWwwAuthenticateParameters(any());
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

		@BeforeEach
		void setUp() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);
		}

		/**
		 * Updating a client registration in response to an insufficient_scope challenge
		 * widens its scopes.
		 * @see ScopeStepUpTests
		 */
		@Test
		void updateScopes() {
			repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read"));

			boolean result = manager.updateMcpClient(REGISTRATION_ID,
					"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read mcp:write\"");

			assertThat(result).isTrue();
			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
		}

	}

	@Nested
	class RegisterClientResponseHandling {

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

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
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
			configureMocks(DCR_RESPONSE);

			var request = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
				.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.redirectUris(List.of("https://request.example.com/callback"))
				.clientName("Request Client Name")
				.scope("request:scope")
				.build();

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
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
			configureMocks(DCR_RESPONSE);

			manager.registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL,
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
					DynamicClientRegistrationRequest.builder().build());

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		}

		private void configureMocks(String dcrResponse) {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(null, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			when(clientRegistrationService.getAuthorizationServerMetadata(ISSUER_URL))
				.thenReturn(authorizationServerMetadata(List.of("mcp:read", "offline_access")));
			when(clientRegistrationService.register(any(), any(ClientRegistration.class)))
				.thenReturn(registrationResponse);
		}

	}

	private static DynamicClientRegistrationResponse dcrResponse(String json) {
		return JsonMapper.builder()
			.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
			.build()
			.readValue(json, DynamicClientRegistrationResponse.class);
	}

	private static ClientRegistration authorizationServerMetadata(List<String> scopesSupported) {
		return ClientRegistration.withRegistrationId("placeholder")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientId("placeholder")
			.tokenUri(ISSUER_URL + "/oauth2/token")
			.authorizationUri(ISSUER_URL + "/oauth2/authorize")
			.issuerUri(ISSUER_URL)
			.providerConfigurationMetadata(Map.of("token_endpoint", ISSUER_URL + "/oauth2/token",
					"authorization_endpoint", ISSUER_URL + "/oauth2/authorize", "registration_endpoint",
					ISSUER_URL + "/connect/register", "scopes_supported", scopesSupported))
			.build();
	}

}
