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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link DelegatingRegisteredClientRepository}.
 *
 * @author Daniel Garnier-Moiroux
 */
class DelegatingRegisteredClientRepositoryTests {

	@Test
	void saveDelegatesToSaveEnabledRepository() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		RegisteredClient client = mock(RegisteredClient.class);
		repository.save(client);

		verify(saveEnabled).save(client);
		verifyNoInteractions(delegate);
	}

	@Test
	void findByIdWhenInSaveEnabledThenReturns() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		when(delegate.findById("client-1")).thenReturn(null);
		when(saveEnabled.findById("client-1")).thenReturn(expectedClient);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(delegate).findById("client-1");
		verify(saveEnabled).findById("client-1");
	}

	@Test
	void findByIdWhenInDelegateThenReturns() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		when(delegate.findById("client-1")).thenReturn(expectedClient);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(delegate).findById("client-1");
		verifyNoInteractions(saveEnabled);
	}

	@Test
	void findByIdWhenNotFoundThenReturnsNull() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		when(saveEnabled.findById(anyString())).thenReturn(null);
		when(delegate.findById(anyString())).thenReturn(null);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isNull();
	}

	@Test
	void findByClientIdWhenInSaveEnabledThenReturns() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		when(delegate.findByClientId("client-1")).thenReturn(null);
		when(saveEnabled.findByClientId("client-1")).thenReturn(expectedClient);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(delegate).findByClientId("client-1");
		verify(saveEnabled).findByClientId("client-1");
	}

	@Test
	void findByClientIdWhenInDelegateThenReturns() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		when(delegate.findByClientId("client-1")).thenReturn(expectedClient);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(delegate).findByClientId("client-1");
		verifyNoInteractions(saveEnabled);
	}

	@Test
	void findByClientIdWhenNotFoundThenReturnsNull() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(List.of(delegate),
				saveEnabled);

		when(saveEnabled.findByClientId(anyString())).thenReturn(null);
		when(delegate.findByClientId(anyString())).thenReturn(null);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isNull();
	}

	@Test
	void saveEnabledInListThenUseFirst() {
		RegisteredClientRepository saveEnabled = mock(RegisteredClientRepository.class);
		RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(
				List.of(saveEnabled, delegate), saveEnabled);

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		when(delegate.findByClientId("client-1")).thenThrow(new RuntimeException("unexpected"));
		when(saveEnabled.findByClientId("client-1")).thenReturn(expectedClient);
		when(delegate.findById("client-1")).thenThrow(new RuntimeException("unexpected"));
		when(saveEnabled.findById("client-1")).thenReturn(expectedClient);

		assertThat(repository.findByClientId("client-1")).isSameAs(expectedClient);
		assertThat(repository.findById("client-1")).isSameAs(expectedClient);
	}

}
