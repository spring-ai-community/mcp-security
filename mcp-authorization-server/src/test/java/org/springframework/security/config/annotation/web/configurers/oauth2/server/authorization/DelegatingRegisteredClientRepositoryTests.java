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
import static org.mockito.BDDMockito.given;
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
	void saveDelegatesToPrimaryRepository() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		RegisteredClient client = mock(RegisteredClient.class);
		repository.save(client);

		verify(primary).save(client);
		verifyNoInteractions(secondary);
	}

	@Test
	void findByIdWhenInPrimaryThenReturns() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		given(primary.findById("client-1")).willReturn(expectedClient);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verifyNoInteractions(secondary);
	}

	@Test
	void findByIdWhenInSecondaryThenReturns() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		given(primary.findById("client-1")).willReturn(null);
		given(secondary.findById("client-1")).willReturn(expectedClient);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(primary).findById("client-1");
		verify(secondary).findById("client-1");
	}

	@Test
	void findByIdWhenNotFoundThenReturnsNull() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		given(primary.findById(anyString())).willReturn(null);
		given(secondary.findById(anyString())).willReturn(null);

		RegisteredClient actualClient = repository.findById("client-1");

		assertThat(actualClient).isNull();
	}

	@Test
	void findByClientIdWhenInPrimaryThenReturns() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		given(primary.findByClientId("client-1")).willReturn(expectedClient);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verifyNoInteractions(secondary);
	}

	@Test
	void findByClientIdWhenInSecondaryThenReturns() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		RegisteredClient expectedClient = mock(RegisteredClient.class);
		given(primary.findByClientId("client-1")).willReturn(null);
		given(secondary.findByClientId("client-1")).willReturn(expectedClient);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isSameAs(expectedClient);
		verify(primary).findByClientId("client-1");
		verify(secondary).findByClientId("client-1");
	}

	@Test
	void findByClientIdWhenNotFoundThenReturnsNull() {
		RegisteredClientRepository primary = mock(RegisteredClientRepository.class);
		RegisteredClientRepository secondary = mock(RegisteredClientRepository.class);
		DelegatingRegisteredClientRepository repository = new DelegatingRegisteredClientRepository(primary,
				List.of(secondary));

		given(primary.findByClientId(anyString())).willReturn(null);
		given(secondary.findByClientId(anyString())).willReturn(null);

		RegisteredClient actualClient = repository.findByClientId("client-1");

		assertThat(actualClient).isNull();
	}

}
