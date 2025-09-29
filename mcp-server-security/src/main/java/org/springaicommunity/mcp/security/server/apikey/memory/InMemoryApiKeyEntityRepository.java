/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.server.apikey.memory;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;

/**
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryApiKeyEntityRepository<T extends ApiKeyEntity> implements ApiKeyEntityRepository<T> {

	private final Map<String, T> apiKeys = new ConcurrentHashMap<>();

	public InMemoryApiKeyEntityRepository() {
	}

	public InMemoryApiKeyEntityRepository(Collection<T> apiKeyEntities) {
		apiKeyEntities.forEach(entity -> this.apiKeys.put(entity.getId(), entity));
	}

	@Nullable
	@Override
	public T findByKeyId(String keyId) {
		return apiKeys.get(keyId).copy();
	}

	public void addApiKey(T value) {
		this.apiKeys.put(value.getId(), value);
	}

	public void removeApiKey(String keyId) {
		this.apiKeys.remove(keyId);
	}

	public boolean containsApiKey(String keyId) {
		return this.apiKeys.containsKey(keyId);
	}

}