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

package org.springaicommunity.mcp.security.client.sync.oauth2.metadata;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parameters from a {@code WWW-Authenticate} header's {@code Bearer} challenge for OAuth2
 * Protected Resources.
 * <p>
 * Only {@code Bearer} challenges are considered; other challenge types are discarded.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9110.html#name-www-authenticate">RFC
 * 9110 - WWW-Authenticate</a>
 */
public final class WwwAuthenticateParameters {

	private static final Logger log = LoggerFactory.getLogger(WwwAuthenticateParameters.class);

	private static final Pattern CHALLENGE_PATTERN = Pattern
		.compile("(\\S+)\\s+((?:[\\w.-]+\\s*=\\s*(?:\"[^\"]*\"|[^\\s,]+)(?:\\s*,\\s*)?)*)");

	private static final Pattern AUTH_PARAM_PATTERN = Pattern.compile("([\\w.-]+)\\s*=\\s*(?:\"([^\"]*)\"|([^\\s,]+))");

	private final String resourceMetadata;

	private final Map<String, String> parameters;

	private WwwAuthenticateParameters(String resourceMetadata, Map<String, String> parameters) {
		this.resourceMetadata = resourceMetadata;
		this.parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
	}

	public String getResourceMetadata() {
		return this.resourceMetadata;
	}

	public @Nullable String getScope() {
		return this.parameters.get("scope");
	}

	public @Nullable String getError() {
		return this.parameters.get("error");
	}

	public @Nullable String getParameter(String parameterName) {
		return this.parameters.get(parameterName);
	}

	/**
	 * Parse a {@code WWW-Authenticate} header value into
	 * {@link WwwAuthenticateParameters}. Only the first {@code Bearer} challenge is
	 * parsed; other challenge types are logged and discarded.
	 * @param wwwAuthenticateHeader the raw header value
	 * @return the parsed parameters, or {@code null} when the header does not contain a
	 * {@code Bearer} challenge with a {@code resource_metadata} parameter
	 */
	public static @Nullable WwwAuthenticateParameters parse(String wwwAuthenticateHeader) {
		Matcher challengeMatcher = CHALLENGE_PATTERN.matcher(wwwAuthenticateHeader.trim());
		while (challengeMatcher.find()) {
			String scheme = challengeMatcher.group(1);
			if (!"Bearer".equalsIgnoreCase(scheme)) {
				log.info("Discarding non-Bearer WWW-Authenticate challenge type: {}", scheme);
				continue;
			}

			String paramString = challengeMatcher.group(2);
			Map<String, String> params = new LinkedHashMap<>();
			Matcher paramMatcher = AUTH_PARAM_PATTERN.matcher(paramString);
			while (paramMatcher.find()) {
				String name = paramMatcher.group(1);
				String value = paramMatcher.group(2) != null ? paramMatcher.group(2) : paramMatcher.group(3);
				params.put(name, value);
			}

			String resourceMetadata = params.get("resource_metadata");
			if (resourceMetadata == null) {
				return null;
			}

			return new WwwAuthenticateParameters(resourceMetadata, params);
		}
		return null;
	}

	@Override
	public String toString() {
		return "WwwAuthenticateParameters[resourceMetadata=%s, parameters=%s]".formatted(this.resourceMetadata,
				this.parameters);
	}

}
