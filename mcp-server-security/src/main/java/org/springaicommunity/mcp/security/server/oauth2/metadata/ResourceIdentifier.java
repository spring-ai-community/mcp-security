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
package org.springaicommunity.mcp.security.server.oauth2.metadata;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Joe Grandja
 */
public final class ResourceIdentifier {

	private final String path;

	public ResourceIdentifier(String path) {
		Assert.hasText(path, "path cannot be empty");
		this.path = path;
	}

	public String getPath() {
		return this.path;
	}

	public String getResource() {
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder
			.getRequestAttributes();
		var request = requestAttributes.getRequest();

		return UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
			.replacePath(this.getPath())
			.replaceQuery(null)
			.fragment(null)
			.toUriString();
	}

}