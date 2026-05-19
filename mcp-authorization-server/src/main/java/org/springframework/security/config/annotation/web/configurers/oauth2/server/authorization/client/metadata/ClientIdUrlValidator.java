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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata;

import java.net.URI;

import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.util.StringUtils;

/**
 * An {@link UrlValidator} implementing Client ID Metadata Document constraints.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-01.html#name-client-identifier">OAuth
 * Client ID Metadata Document > 3. Client Identifier</a>
 */
public class ClientIdUrlValidator extends DefaultUrlValidator {

	public ClientIdUrlValidator() {
		super();
	}

	public ClientIdUrlValidator(boolean allowLoopback) {
		super(allowLoopback);
	}

	@Override
	public void validateUrl(URI uri) throws InvalidUrlException {
		// Must be HTTPS
		// Must not contain path-traversal
		super.validateUrl(uri);

		if (!StringUtils.hasText(uri.getPath())) {
			throw new InvalidUrlException("Client Identifier must have a path component [%s]".formatted(uri),
					uri.toString());
		}

		if (StringUtils.hasText(uri.getFragment())) {
			throw new InvalidUrlException("Client Identifier must not have a fragment component [%s]".formatted(uri),
					uri.toString());
		}

		if (StringUtils.hasText(uri.getUserInfo())) {
			throw new InvalidUrlException(
					"Client Identifier must not contain a username or password [%s]".formatted(uri), uri.toString());
		}
	}

}
