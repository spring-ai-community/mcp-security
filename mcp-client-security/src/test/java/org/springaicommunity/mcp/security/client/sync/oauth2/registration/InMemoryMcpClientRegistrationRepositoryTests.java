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
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link InMemoryMcpClientRegistrationRepository}.
 *
 * @author Daniel Garnier-Moiroux
 */
class InMemoryMcpClientRegistrationRepositoryTests {

	private InMemoryMcpClientRegistrationRepository repository;

	@BeforeEach
	void setUp() {
		this.repository = new InMemoryMcpClientRegistrationRepository();
	}

	@Test
	void addClientRegistrationWhenNewThenAdded() {
		ClientRegistration registration = createRegistration("test-client");
		this.repository.addClientRegistration(registration, "test-resource");

		assertThat(this.repository.findByRegistrationId("test-client")).isSameAs(registration);
		assertThat(this.repository.findResourceIdByRegistrationId("test-client")).isEqualTo("test-resource");
	}

	@Test
	void addClientRegistrationWhenExistingThenIgnored() {
		ClientRegistration registration1 = createRegistration("test-client");
		ClientRegistration registration2 = createRegistration("test-client");

		this.repository.addClientRegistration(registration1, "resource-1");
		this.repository.addClientRegistration(registration2, "resource-2");

		assertThat(this.repository.findByRegistrationId("test-client")).isSameAs(registration1);
		assertThat(this.repository.findResourceIdByRegistrationId("test-client")).isEqualTo("resource-1");
	}

	@Test
	void addClientRegistrationWhenNullResourceIdThenNotStored() {
		ClientRegistration registration = createRegistration("test-client");
		this.repository.addClientRegistration(registration, null);

		assertThat(this.repository.findByRegistrationId("test-client")).isSameAs(registration);
		assertThat(this.repository.findResourceIdByRegistrationId("test-client")).isNull();
	}

	@Test
	void updateClientRegistrationWhenExistingThenUpdated() {
		ClientRegistration registration = createRegistration("test-client");
		this.repository.addClientRegistration(registration, "test-resource");

		this.repository.updateClientRegistration("test-client", builder -> builder.clientId("updated-client-id"));

		ClientRegistration updated = this.repository.findByRegistrationId("test-client");
		assertThat(updated).isNotNull();
		assertThat(updated).isNotSameAs(registration);
		assertThat(updated.getClientId()).isEqualTo("updated-client-id");
	}

	@Test
	void updateClientRegistrationWhenNotExistingThenIgnored() {
		this.repository.updateClientRegistration("non-existent", builder -> builder.clientId("updated-client-id"));

		assertThat(this.repository.findByRegistrationId("non-existent")).isNull();
	}

	@Test
	void findResourceIdByRegistrationIdWhenNotExistingThenNull() {
		assertThat(this.repository.findResourceIdByRegistrationId("non-existent")).isNull();
	}

	@Test
	void findByRegistrationIdWhenNotExistingThenNull() {
		assertThat(this.repository.findByRegistrationId("non-existent")).isNull();
	}

	@Test
	void iteratorWhenEmptyThenEmpty() {
		assertThat(this.repository.iterator()).isExhausted();
	}

	@Test
	void iteratorWhenHasElementsThenReturnsElements() {
		ClientRegistration registration1 = createRegistration("client-1");
		ClientRegistration registration2 = createRegistration("client-2");

		this.repository.addClientRegistration(registration1, "resource-1");
		this.repository.addClientRegistration(registration2, "resource-2");

		assertThat(this.repository).containsExactlyInAnyOrder(registration1, registration2);
	}

	private ClientRegistration createRegistration(String registrationId) {
		return ClientRegistration.withRegistrationId(registrationId)
			.clientId(registrationId + "-id")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.tokenUri("https://example.com/token")
			.build();
	}

}
