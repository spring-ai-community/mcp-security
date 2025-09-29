package org.springaicommunity.mcp.security.server.apikey.memory;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntity;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;

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