package org.springaicommunity.mcp.security.server.apikey;

import org.jspecify.annotations.Nullable;

public interface ApiKeyEntityRepository<T extends ApiKeyEntity> {

	@Nullable
	T findByKeyId(String keyId);

}