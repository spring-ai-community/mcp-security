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

package org.springaicommunity.mcp.security.server.apikey.web;

import java.util.Collections;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationConverter} which extracts the API key from a
 * {@link HttpServletRequest}, and returns a {@link ApiKeyAuthenticationToken}.
 */
public class ApiKeyAuthenticationConverter implements AuthenticationConverter {

	private final String apiKeyHeaderName;

	public ApiKeyAuthenticationConverter(String apiKeyHeaderName) {
		Assert.hasText(apiKeyHeaderName, "apiKeyHeaderName cannot be blank");
		this.apiKeyHeaderName = apiKeyHeaderName;
	}

	@Override
	@Nullable
	public Authentication convert(HttpServletRequest request) {
		var apiKeyValues = Collections.list(request.getHeaders(this.apiKeyHeaderName));
		if (apiKeyValues.isEmpty()) {
			return null;
		}
		if (apiKeyValues.size() > 1) {
			throw new BadCredentialsException(
					"%s must have a single value, found %s".formatted(this.apiKeyHeaderName, apiKeyValues.size()));
		}
		String apiKey = apiKeyValues.get(0);

		if (!StringUtils.hasText(apiKey)) {
			return null;
		}

		try {
			return ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from(apiKey));
		}
		catch (IllegalArgumentException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

}
