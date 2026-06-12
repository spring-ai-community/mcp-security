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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Daniel Garnier-Moiroux
 */
class ScopeStepUpTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String ISSUER_URL = "https://auth.example.com";

	private static final ClientRegistration CLIENT_REGISTRATION = ClientRegistration.withRegistrationId(REGISTRATION_ID)
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
		.clientId("existing-client-id")
		.tokenUri(ISSUER_URL + "/oauth2/token")
		.build();

	private static final String RESOURCE_ID = "https://mcp.example.com";

	private final McpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final ScopeStepUp scopeStepUp = new ScopeStepUp(repository);

	@BeforeEach
	void setUp() {
		repository.addClientRegistration(CLIENT_REGISTRATION, RESOURCE_ID);
	}

	@Test
	@DisplayName("Does not update scopes when the error is not insufficient_scope")
	void noopErrorIsNotInsufficientScope() {
		boolean result = scopeStepUp.updateOAuth2ClientScopes(REGISTRATION_ID,
				"Bearer resource_metadata=\"https://example.com/\", error=\"invalid_token\", scope=\"mcp:read\"");

		assertThat(result).isFalse();
		var registration = repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(registration).isNotNull();
		assertThat(registration.getScopes()).isNullOrEmpty();
	}

	@Test
	@DisplayName("Does not update scopes when not provided in header")
	void noopNoScope() {
		boolean result = scopeStepUp.updateOAuth2ClientScopes(REGISTRATION_ID,
				"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\"");

		assertThat(result).isFalse();
		var registration = repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(registration).isNotNull();
		assertThat(registration.getScopes()).isNullOrEmpty();
	}

	@Test
	@DisplayName("Does not update scopes when scopes are already present")
	void noopScopesAlreadyPresent() {
		repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read", "mcp:write"));

		boolean result = scopeStepUp.updateOAuth2ClientScopes(REGISTRATION_ID,
				"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read\"");

		assertThat(result).isFalse();
		var registration = repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(registration).isNotNull();
		assertThat(registration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
	}

	@Test
	void updateScopes() {
		repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read"));

		boolean result = scopeStepUp.updateOAuth2ClientScopes(REGISTRATION_ID,
				"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:read mcp:write\"");

		assertThat(result).isTrue();
		var registration = repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(registration).isNotNull();
		assertThat(registration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
	}

	@Test
	@DisplayName("Adds new scope from WWW-Authenticate header without removing existing scopes")
	void addsScopesWithoutReplacingExisting() {
		repository.updateClientRegistration(REGISTRATION_ID, existing -> existing.scope("mcp:read"));

		boolean result = scopeStepUp.updateOAuth2ClientScopes(REGISTRATION_ID,
				"Bearer resource_metadata=\"https://example.com/\", error=\"insufficient_scope\", scope=\"mcp:write\"");

		assertThat(result).isTrue();
		var registration = repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(registration).isNotNull();
		assertThat(registration.getScopes()).containsExactlyInAnyOrder("mcp:read", "mcp:write");
	}

}
