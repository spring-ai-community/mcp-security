package org.springaicommunity.mcp.security.server.apikey;

import org.jspecify.annotations.Nullable;

public interface ApiKey {

	String getId();

	@Nullable
	String getSecret();

}
