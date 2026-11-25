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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration.dcr;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.ProtectedResourceMetadata;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.security.config.Customizer;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class DcrMcpOAuth2ClientManagerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com";

	private static final String ISSUER_URL = "https://auth.example.com";

	private static final String OFFLINE_ACCESS_ISSUER_URL = "https://offline.example.com";

	private static final ClientRegistration CLIENT_REGISTRATION = ClientRegistration.withRegistrationId(REGISTRATION_ID)
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
		.clientId("existing-client-id")
		.tokenUri(ISSUER_URL + "/oauth2/token")
		.build();

	private static final String RESOURCE_ID = "https://mcp.example.com";

	private static final String BASE_URL = "https://app.example.com";

	private static final String REDIRECT_URI = BASE_URL + "/authorize/oauth2/code/" + REGISTRATION_ID;

	private static final DynamicClientRegistrationRequest REGISTRATION_REQUEST = DynamicClientRegistrationRequest
		.authorizationCode(REDIRECT_URI);

	private static final String DCR_RESPONSE = "{\"client_id\": \"client-id-123\"}\n";

	private static MockedStatic<ClientRegistrations> clientRegistrationsMock;

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final DynamicClientRegistrationService clientRegistrationService = mock(
			DynamicClientRegistrationService.class);

	private final McpMetadataDiscoveryService discovery = mock(McpMetadataDiscoveryService.class);

	private final UrlValidator urlValidator = mock(UrlValidator.class);

	private final DcrMcpOAuth2ClientManager manager = new DcrMcpOAuth2ClientManager(this.repository,
			this.clientRegistrationService, this.discovery, this.urlValidator);

	@BeforeAll
	static void beforeAll() {
		clientRegistrationsMock = mockStatic(ClientRegistrations.class);
		clientRegistrationsMock.when(() -> ClientRegistrations.fromIssuerLocation(ISSUER_URL))
			.thenReturn(ClientRegistration.withRegistrationId("placeholder")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId("placeholder")
				.tokenUri(ISSUER_URL + "/oauth2/token")
				.authorizationUri(ISSUER_URL + "/oauth2/authorize")
				.providerConfigurationMetadata(Map.of("token_endpoint", ISSUER_URL + "/oauth2/token",
						"authorization_endpoint", ISSUER_URL + "/oauth2/authorize")));
		clientRegistrationsMock.when(() -> ClientRegistrations.fromIssuerLocation(OFFLINE_ACCESS_ISSUER_URL))
			.thenAnswer(invocation -> ClientRegistration.withRegistrationId("placeholder")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId("placeholder")
				.tokenUri(OFFLINE_ACCESS_ISSUER_URL + "/oauth2/token")
				.authorizationUri(OFFLINE_ACCESS_ISSUER_URL + "/oauth2/authorize")
				.providerConfigurationMetadata(Map.of("token_endpoint", OFFLINE_ACCESS_ISSUER_URL + "/oauth2/token",
						"authorization_endpoint", OFFLINE_ACCESS_ISSUER_URL + "/oauth2/authorize", "scopes_supported",
						List.of("mcp:read", "offline_access"))));

	}

	@AfterAll
	static void afterAll() {
		clientRegistrationsMock.close();
	}

	@Nested
	class RegisterClientWithRequest {

		@Test
		void throwsWhenRegistrationAlreadyExists() {
			repository.save(CLIENT_REGISTRATION, RESOURCE_ID);

			assertThatThrownBy(() -> manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST))
				.isInstanceOf(ClientAlreadyExistsException.class);

			verifyNoInteractions(discovery);
			verifyNoInteractions(clientRegistrationService);
		}

		@Test
		void register() throws Exception {
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

			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST);

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
		void registerScopesFromWwwAuthenticateHeader() throws Exception {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:read mcp:write\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:delete"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);

			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).isNotNull().containsExactly("mcp:read", "mcp:write");
		}

		@Test
		@DisplayName("Registers scopes from Protected Resource Metadata when absent from WWW-Authenticate header")
		void registerScopesFromProtectedResourceMetadata() throws Exception {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL),
					List.of("mcp:tools", "mcp:prompts"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);

			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:tools", "mcp:prompts");
		}

		@Test
		@DisplayName("Registers scopes from user request")
		void preservesRequestScopesWhenAlreadySet() throws Exception {
			var wwwAuthParams = WwwAuthenticateParameters.parse(
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"mcp:admin\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), List.of("mcp:tools"));
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var request = DynamicClientRegistrationRequest.from(REGISTRATION_REQUEST).scope("mcp:custom").build();

			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, request);

			var registration = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(registration).isNotNull();
			assertThat(registration.getScopes()).containsExactly("mcp:custom");
		}

		@Test
		@DisplayName("Does not apply the registration request customizer")
		void doesNotApplyRegistrationRequestCustomizer() throws Exception {
			manager.setRegistrationRequestCustomizer(builder -> builder.clientName("customized"));

			var request = register(ISSUER_URL, null, Customizer.withDefaults());

			assertThat(request.getClientName()).isNull();
			assertThat(request.getRedirectUris()).containsExactly(REDIRECT_URI);
		}

		@Test
		@DisplayName("Does not request offline_access for client_credentials clients")
		void doesNotRequestOfflineAccessForClientCredentials() throws Exception {
			var request = registerWithOfflineAccessIssuer(
					builder -> builder.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS)));

			assertThat(request.getScope()).isEqualTo("mcp:read");
			assertThat(request.getGrantTypes()).containsExactly("client_credentials");
		}

		@Test
		@DisplayName("Requests offline_access and refresh_token for authorization_code clients")
		void requestsOfflineAccessForAuthorizationCode() throws Exception {
			var request = registerWithOfflineAccessIssuer(Customizer.withDefaults());

			assertThat(request.getScope()).isNotNull();
			assertThat(request.getScope().split(" ")).containsExactlyInAnyOrder("mcp:read", "offline_access");
			assertThat(request.getGrantTypes()).containsExactly("authorization_code", "refresh_token");
		}

		@Test
		@DisplayName("Adds offline_access to scopes set explicitly on the request")
		void requestsOfflineAccessWithExplicitScopes() throws Exception {
			var request = registerWithOfflineAccessIssuer(builder -> builder.scope("mcp:custom"));

			assertThat(request.getScope()).isNotNull();
			assertThat(request.getScope().split(" ")).containsExactlyInAnyOrder("mcp:custom", "offline_access");
		}

		@Test
		@DisplayName("Does not duplicate offline_access when already requested")
		void doesNotDuplicateOfflineAccess() throws Exception {
			var request = registerWithOfflineAccessIssuer(builder -> builder.scope("mcp:custom offline_access"));

			assertThat(request.getScope()).isEqualTo("mcp:custom offline_access");
		}

		@Test
		@DisplayName("Does not request offline_access without the refresh_token grant")
		void doesNotRequestOfflineAccessWithoutRefreshTokenGrant() throws Exception {
			var request = registerWithOfflineAccessIssuer(
					builder -> builder.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE)));

			assertThat(request.getScope()).isEqualTo("mcp:read");
			assertThat(request.getGrantTypes()).containsExactly("authorization_code");
		}

		@Test
		@DisplayName("Does not request offline_access when the authorization server does not list it")
		void doesNotRequestOfflineAccessWhenUnsupported() throws Exception {
			var request = register(ISSUER_URL, "mcp:read", Customizer.withDefaults());

			assertThat(request.getScope()).isEqualTo("mcp:read");
		}

		@Test
		@DisplayName("Does not request offline_access when no scopes are found")
		void doesNotRequestOfflineAccessWithoutScopes() throws Exception {
			var request = register(OFFLINE_ACCESS_ISSUER_URL, null, Customizer.withDefaults());

			assertThat(request.getScope()).isNull();
		}

		private DynamicClientRegistrationRequest registerWithOfflineAccessIssuer(
				Customizer<DynamicClientRegistrationRequest.Builder> requestCustomizer) throws Exception {
			return register(OFFLINE_ACCESS_ISSUER_URL, "mcp:read", requestCustomizer);
		}

		/**
		 * Register a client against the given issuer, with an optional scope in the
		 * WWW-Authenticate header, and return the request sent to the DCR endpoint.
		 */
		private DynamicClientRegistrationRequest register(String issuerUrl, @Nullable String wwwAuthenticateScope,
				Customizer<DynamicClientRegistrationRequest.Builder> requestCustomizer) throws Exception {
			var header = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";
			if (wwwAuthenticateScope != null) {
				header += ", scope=\"" + wwwAuthenticateScope + "\"";
			}
			var wwwAuthParams = WwwAuthenticateParameters.parse(header);
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(issuerUrl), null);
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);

			var requestBuilder = DynamicClientRegistrationRequest.from(REGISTRATION_REQUEST);
			requestCustomizer.customize(requestBuilder);
			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, requestBuilder.build());

			var captor = ArgumentCaptor.forClass(DynamicClientRegistrationRequest.class);
			verify(clientRegistrationService).register(captor.capture(), eq(issuerUrl));
			return captor.getValue();
		}

		@Test
		@DisplayName("Throws when configuration metadata contains invalid URL")
		void throwsWhenConfigurationMetadataContainsInvalidUrl() throws Exception {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			configureMocks(wwwAuthParams, prm, DCR_RESPONSE);
			var tokenUrl = ISSUER_URL + "/oauth2/token";
			doThrow(new InvalidUrlException("Invalid test url", tokenUrl)).when(urlValidator).validateUrl(tokenUrl);

			assertThatThrownBy(() -> manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Invalid token_endpoint [value=%s]: Invalid test url".formatted(tokenUrl));
		}

		@Test
		void throwsWhenDcrNotSupported() throws Exception {
			var wwwAuthParams = WwwAuthenticateParameters
				.parse("Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"");
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			when(discovery.getWwwAuthenticateParameters(MCP_SERVER_URL)).thenReturn(wwwAuthParams);
			when(discovery.getMcpMetadata(MCP_SERVER_URL, wwwAuthParams))
				.thenReturn(new McpMetadata(wwwAuthParams, prm));
			when(clientRegistrationService.register(any(), eq(ISSUER_URL)))
				.thenThrow(new DcrNotSupportedException(ISSUER_URL));

			assertThatThrownBy(() -> manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, REGISTRATION_REQUEST))
				.isInstanceOf(DcrNotSupportedException.class)
				.hasMessage("Issuer %s does not support DCR".formatted(ISSUER_URL));

			assertThat(repository.findByRegistrationId(REGISTRATION_ID)).isNull();
		}

		private void configureMocks(@Nullable WwwAuthenticateParameters wwwAuthParams,
				ProtectedResourceMetadata protectedResourceMetadata, String dcrResponse) throws Exception {
			when(discovery.getWwwAuthenticateParameters(MCP_SERVER_URL)).thenReturn(wwwAuthParams);
			var mcpMetadata = new McpMetadata(wwwAuthParams, protectedResourceMetadata);
			when(discovery.getMcpMetadata(MCP_SERVER_URL, wwwAuthParams)).thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			var authzServers = Objects.requireNonNull(protectedResourceMetadata.authorizationServers());
			when(clientRegistrationService.register(any(), eq(authzServers.get(0)))).thenReturn(registrationResponse);
		}

	}

	@Nested
	class RegisterClient {

		private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

		@Test
		void throwsWhenRegistrationAlreadyExists() {
			repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);

			assertThatThrownBy(
					() -> manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(ClientAlreadyExistsException.class)
				.hasMessageContaining(REGISTRATION_ID);

			verifyNoInteractions(discovery);
			verifyNoInteractions(clientRegistrationService);
		}

		@Test
		void register() throws Exception {
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
			when(clientRegistrationService.register(any(), eq(ISSUER_URL))).thenReturn(registrationResponse);

			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

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

		@Test
		void throwsWhenDcrNotSupported() throws Exception {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(new McpMetadata(null, prm));
			when(clientRegistrationService.register(any(), eq(ISSUER_URL)))
				.thenThrow(new DcrNotSupportedException(ISSUER_URL));

			assertThatThrownBy(
					() -> manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
				.isInstanceOf(DcrNotSupportedException.class)
				.hasMessage("Issuer %s does not support DCR".formatted(ISSUER_URL));

			assertThat(repository.findByRegistrationId(REGISTRATION_ID)).isNull();
		}

	}

	@Nested
	class UpdateMcpClient {

		@BeforeEach
		void setUp() throws Exception {
			repository.save(CLIENT_REGISTRATION, RESOURCE_ID);
		}

		/**
		 * Updating a client registration in response to an insufficient_scope challenge
		 * widens its scopes. See {@code ScopeStepUpTests}.
		 */
		@Test
		void updateScopes() throws Exception {
			repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read"));

			boolean result = manager.updateScopes(REGISTRATION_ID,
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
		void usesResponseValuesOverRequestValues() throws Exception {
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
			manager.setRegistrationRequestCustomizer(
					request -> request.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
						.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.clientName("Request Client Name")
						.scope("request:scope"));

			registerClient();

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
		void fallsBackToRequestValuesWhenResponseValuesAreNull() throws Exception {
			configureMocks(DCR_RESPONSE);

			manager.setRegistrationRequestCustomizer(
					request -> request.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
						.tokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.redirectUris(List.of("https://request.example.com/callback"))
						.clientName("Request Client Name")
						.scope("request:scope"));

			registerClient();

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
			assertThat(saved.getRedirectUri()).isEqualTo("https://request.example.com/callback");
			assertThat(saved.getScopes()).containsExactly("request:scope");
			assertThat(saved.getClientName()).isEqualTo("Request Client Name");
		}

		@Test
		void defaultsToAuthorizationCodeRequest() throws Exception {
			configureMocks(DCR_RESPONSE);

			registerClient();

			var captor = ArgumentCaptor.forClass(DynamicClientRegistrationRequest.class);
			verify(clientRegistrationService).register(captor.capture(), eq(ISSUER_URL));
			assertThat(captor.getValue().getGrantTypes()).containsExactly("authorization_code", "refresh_token");
			assertThat(captor.getValue().getRedirectUris()).containsExactly(REDIRECT_URI);
			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
			assertThat(saved.getRedirectUri()).isEqualTo(REDIRECT_URI);
		}

		@Test
		void customizesClientRegistration() throws Exception {
			configureMocks(DCR_RESPONSE);
			manager.setClientRegistrationCustomizer(registration -> registration.clientName("Customized"));

			registerClient();

			var saved = repository.findByRegistrationId(REGISTRATION_ID);
			assertThat(saved).isNotNull();
			assertThat(saved.getClientId()).isEqualTo("client-id-123");
			assertThat(saved.getClientName()).isEqualTo("Customized");
		}

		private void registerClient() throws Exception {
			manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL,
					"Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
					BASE_URL);
		}

		private void configureMocks(String dcrResponse) throws Exception {
			var prm = new ProtectedResourceMetadata(RESOURCE_ID, List.of(ISSUER_URL), null);
			var mcpMetadata = new McpMetadata(null, prm);
			when(discovery.getMcpMetadata(eq(MCP_SERVER_URL), any())).thenReturn(mcpMetadata);
			var registrationResponse = dcrResponse(dcrResponse);
			when(clientRegistrationService.register(any(), eq(ISSUER_URL))).thenReturn(registrationResponse);
		}

	}

	private static DynamicClientRegistrationResponse dcrResponse(String json) {
		return JsonMapper.builder()
			.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
			.build()
			.readValue(json, DynamicClientRegistrationResponse.class);
	}

}
