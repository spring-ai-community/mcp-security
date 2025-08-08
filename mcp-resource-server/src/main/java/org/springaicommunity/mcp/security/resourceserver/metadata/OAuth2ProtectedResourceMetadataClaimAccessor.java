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
package org.springaicommunity.mcp.security.resourceserver.metadata;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the claims a Resource Server describes about its
 * configuration, used in OAuth 2.0 Protected Resource Metadata.
 *
 * @author Joe Grandja
 * @see ClaimAccessor
 * @see OAuth2ProtectedResourceMetadata
 */
public interface OAuth2ProtectedResourceMetadataClaimAccessor extends ClaimAccessor {

	default URL getResource() {
		return getClaimAsURL(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE);
	}

	default List<URL> getAuthorizationServers() {
		List<String> authorizationServers = getClaimAsStringList(
				OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS);
		List<URL> urls = new ArrayList<>();
		authorizationServers.forEach((authorizationServer) -> {
			try {
				urls.add(new URI(authorizationServer).toURL());
			}
			catch (Exception ex) {
				throw new IllegalArgumentException("Failed to convert authorization_server to URL", ex);
			}
		});
		return urls;
	}

	default List<String> getScopes() {
		return getClaimAsStringList(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED);
	}

	default List<String> getBearerMethodsSupported() {
		return getClaimAsStringList(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED);
	}

	default String getResourceName() {
		return getClaimAsString(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME);
	}

}