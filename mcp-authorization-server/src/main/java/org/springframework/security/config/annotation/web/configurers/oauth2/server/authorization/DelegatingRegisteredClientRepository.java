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
 * repositories. An optional repository can be provided to save new clients. The
 * save-enabled repository will be added to the list of delegates if not already present.
 * <p>
 * This is used to support both Client ID Metadata Document-based clients, Dynamic Client
 * Registration clients, and regular, pre-registered clients.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class DelegatingRegisteredClientRepository implements RegisteredClientRepository {

	private final List<RegisteredClientRepository> repositories;

	private final @Nullable RegisteredClientRepository saveEnabledRepository;

	/**
	 * Construct a read-only repository.
	 * @param repositories delegate repositories
	 */
	public DelegatingRegisteredClientRepository(List<RegisteredClientRepository> repositories) {
		this(repositories, null);
	}

	/**
	 * Construct a delegating repository with an optional save-enabled repository.
	 * @param repositories delegate repositories
	 * @param saveEnabledRepository repository where new clients are saved
	 */
	public DelegatingRegisteredClientRepository(List<RegisteredClientRepository> repositories,
			@Nullable RegisteredClientRepository saveEnabledRepository) {
		this.saveEnabledRepository = saveEnabledRepository;
		this.repositories = new ArrayList<>();
		this.repositories.addAll(repositories);
		if (saveEnabledRepository != null && !this.repositories.contains(saveEnabledRepository)) {
			this.repositories.add(saveEnabledRepository);
		}
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		if (this.saveEnabledRepository != null) {
			this.saveEnabledRepository.save(registeredClient);
		}
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
