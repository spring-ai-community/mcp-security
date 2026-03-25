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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * In-memory implementation of {@link McpClientRegistrationRepository} that stores
 * {@link ClientRegistration}s and their associated resource identifiers.
 * <p>
 * This implementation is not thread-safe and follows a "last update wins" strategy.
 * Relies on a concurrent hashmap, that is never purged.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryMcpClientRegistrationRepository implements McpClientRegistrationRepository {

	private final Map<String, ClientRegistration> registrations = new ConcurrentHashMap<>();

	private final Map<String, String> resources = new ConcurrentHashMap<>();

	@Override
	public void addClientRegistration(ClientRegistration clientRegistration, @Nullable String resourceId) {
		this.registrations.computeIfAbsent(clientRegistration.getRegistrationId(), id -> {
			if (StringUtils.hasText(resourceId)) {
				this.resources.put(id, resourceId);
			}
			return clientRegistration;
		});
	}

	@Override
	public void updateClientRegistration(String registrationId,
			Consumer<ClientRegistration.Builder> clientRegistrationConsumer) {
		this.registrations.computeIfPresent(registrationId, (id, existingRegistration) -> {
			var builder = ClientRegistration.withClientRegistration(existingRegistration);
			clientRegistrationConsumer.accept(builder);
			return builder.build();
		});
	}

	@Override
	public @Nullable String findResourceIdByRegistrationId(String registrationId) {
		return this.resources.get(registrationId);
	}

	@Override
	public @Nullable ClientRegistration findByRegistrationId(String registrationId) {
		return this.registrations.get(registrationId);
	}

}
