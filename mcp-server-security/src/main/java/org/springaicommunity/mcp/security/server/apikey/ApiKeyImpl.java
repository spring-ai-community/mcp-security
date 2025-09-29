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

package org.springaicommunity.mcp.security.server.apikey;

import org.springframework.util.StringUtils;

/**
 * @author Daniel Garnier-Moiroux
 */
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
