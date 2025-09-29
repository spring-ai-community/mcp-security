package org.springaicommunity.mcp.security.server.apikey;

import org.springframework.util.StringUtils;

public class ApiKeyImpl implements ApiKey {

	private final String id;

	private final String secret;

	private ApiKeyImpl(String id, String secret) {
		this.id = id;
		this.secret = secret;
	}

	public static ApiKey from(String apiKey) {
		if (!StringUtils.hasText(apiKey) || !apiKey.contains(".")) {
			throw new IllegalArgumentException("API key must be in the format <id>.<secret>");
		}
		var parts = apiKey.split("\\.");
		return new ApiKeyImpl(parts[0], parts[1]);
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public String getSecret() {
		return secret;
	}

}
