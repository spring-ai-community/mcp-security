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
import java.net.URISyntaxException;

/**
 * Interface for validating URLs returned by MCP Clients, Servers and Authorization
 * Servers.
 *
 * @see <a
 * href="https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#server-side-request-forgery-ssrf>Security
 * Best Practices: SSRF</a>
 */
public interface UrlValidator {

	void validateUrl(URI url) throws InvalidUrlException;

	default void validateUrl(String url) throws InvalidUrlException {
		try {
			validateUrl(new URI(url));
		}
		catch (URISyntaxException e) {
			throw new InvalidUrlException("Cannot parse url %s".formatted(url), url, e);
		}
	};

}
