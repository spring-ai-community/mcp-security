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

package org.springaicommunity.mcp.security.server.boot;

import java.util.Collections;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.CollectionUtils;
import static org.springaicommunity.mcp.security.server.boot.McpServerSecurityProperties.CONFIG_PREFIX;

@ConfigurationProperties(prefix = CONFIG_PREFIX)
public class McpServerSecurityProperties {

	public static final String CONFIG_PREFIX = "spring.ai.mcp.server.security";

	private static final List<String> DEFAULT_ALLOWED_ORIGINS = List.of("http://localhost:*", "http://127.0.0.1:*",
			"http://[::1]:*", "http://[::]:*");

	private final List<String> allowedOrigins;

	private final @Nullable List<String> allowedHosts;

	public McpServerSecurityProperties(@Nullable List<String> allowedOrigins, @Nullable List<String> allowedHosts) {
		this.allowedOrigins = CollectionUtils.isEmpty(allowedOrigins) ? DEFAULT_ALLOWED_ORIGINS
				: Collections.unmodifiableList(allowedOrigins);
		this.allowedHosts = (allowedHosts == null) ? null : Collections.unmodifiableList(allowedHosts);
	}

	public List<String> getAllowedOrigins() {
		return allowedOrigins;
	}

	public @Nullable List<String> getAllowedHosts() {
		return allowedHosts;
	}

}
