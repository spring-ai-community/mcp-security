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

package org.springaicommunity.mcp.security.client.sync.oauth2;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;

import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link McpResourceParametersConverter}.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpResourceParametersConverterTests {

	private final InMemoryMcpClientRegistrationRepository repository = new InMemoryMcpClientRegistrationRepository();

	private final McpResourceParametersConverter<OAuth2ClientCredentialsGrantRequest> converter = new McpResourceParametersConverter<>(
			this.repository);

	private final ClientRegistration registration = ClientRegistration.withRegistrationId("mcp-server")
		.clientId("client-id")
		.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
		.tokenUri("https://auth.example.com/token")
		.build();

	@Test
	void addsResource() {
		this.repository.save(this.registration, "https://mcp.example.com/mcp");

		var parameters = this.converter.convert(new OAuth2ClientCredentialsGrantRequest(this.registration));

		assertThat(parameters).containsOnlyKeys("resource");
		assertThat(parameters.get("resource")).containsExactly("https://mcp.example.com/mcp");
	}

	@Test
	void noResourceWhenRegistrationHasNoResource() {
		this.repository.save(this.registration, null);

		var parameters = this.converter.convert(new OAuth2ClientCredentialsGrantRequest(this.registration));

		assertThat(parameters).isEmpty();
	}

	@Test
	void noResourceWhenRegistrationUnknown() {
		var parameters = this.converter.convert(new OAuth2ClientCredentialsGrantRequest(this.registration));

		assertThat(parameters).isEmpty();
	}

	@Test
	@SuppressWarnings("NullAway") // intentionally passing null to verify it is rejected
	void requiresRepository() {
		assertThatIllegalArgumentException().isThrownBy(() -> new McpResourceParametersConverter<>(null))
			.withMessage("clientRegistrationRepository cannot be null");
	}

}
