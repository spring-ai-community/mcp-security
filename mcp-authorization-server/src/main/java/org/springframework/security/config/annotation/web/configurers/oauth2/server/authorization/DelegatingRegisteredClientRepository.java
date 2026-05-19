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

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * An implementation of {@link RegisteredClientRepository} that delegates to other
 * repositories. The primary repository will be used to save new clients.
 * <p>
 * This is used to support both Client ID Metadata Document-based clients, and regular,
 * pre-registered clients.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class DelegatingRegisteredClientRepository implements RegisteredClientRepository {

	private final List<RegisteredClientRepository> repositories;

	private final RegisteredClientRepository defaultRepository;

	public DelegatingRegisteredClientRepository(RegisteredClientRepository primaryRepository,
			List<RegisteredClientRepository> repositories) {
		this.defaultRepository = primaryRepository;
		this.repositories = new ArrayList<>();
		this.repositories.add(primaryRepository);
		this.repositories.addAll(repositories);
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		this.defaultRepository.save(registeredClient);
	}

	@Override
	public @Nullable RegisteredClient findById(String id) {
		for (var repository : this.repositories) {
			var client = repository.findById(id);
			if (client != null) {
				return client;
			}
		}
		return null;
	}

	@Override
	public @Nullable RegisteredClient findByClientId(String clientId) {
		for (var repository : this.repositories) {
			var client = repository.findByClientId(clientId);
			if (client != null) {
				return client;
			}
		}
		return null;
	}

}
