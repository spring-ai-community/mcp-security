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

package org.springaicommunity.mcp.security.common.url;

import java.net.URI;

/**
 * Default implementation of {@link UrlValidator} that enforces HTTPS URLs and optionally
 * allows HTTP loopback addresses.
 * <p>
 * For production use-cases, ensure your implementation security best practices.
 *
 * @see <a
 * href="https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#server-side-request-forgery-ssrf>Security
 * Best Practices: SSRF</a>
 */
public class DefaultUrlValidator implements UrlValidator {

	public final boolean allowLoopback;

	public DefaultUrlValidator() {
		this(false);
	}

	public DefaultUrlValidator(boolean allowLoopback) {
		this.allowLoopback = allowLoopback;
	}

	@Override
	public void validateUrl(URI uri) throws InvalidUrlException {
		if ("https".equalsIgnoreCase(uri.getScheme())) {
			return;
		}

		if (this.allowLoopback && "http".equalsIgnoreCase(uri.getScheme()) && isLoopback(uri.getHost())) {
			return;
		}

		throw new InvalidUrlException("URL %s must have HTTPS scheme".formatted(uri), uri.toString());
	}

	private boolean isLoopback(String host) {
		if (host == null) {
			return false;
		}
		return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
	}

}
