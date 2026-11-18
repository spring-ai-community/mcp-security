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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

import java.util.Collection;
import java.util.Map;

import org.jspecify.annotations.Nullable;

/**
 * Support for the {@code offline_access} scope, used to obtain a refresh token. Clients
 * should only request it when the authorization server lists it in its
 * {@code scopes_supported} metadata.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization">MCP
 * authorization, refresh tokens</a>
 */
public final class OfflineAccess {

	public static final String OFFLINE_ACCESS = "offline_access";

	private static final String SCOPES_SUPPORTED = "scopes_supported";

	private OfflineAccess() {
	}

	/**
	 * Whether the authorization server lists {@code offline_access}.
	 * @param authorizationServerMetadata the authorization server metadata, as in
	 * {@code ProviderDetails#getConfigurationMetadata()}
	 * @return {@code true} if {@code scopes_supported} contains {@code offline_access}
	 */
	public static boolean isSupported(@Nullable Map<String, Object> authorizationServerMetadata) {
		if (authorizationServerMetadata == null) {
			return false;
		}
		return authorizationServerMetadata.get(SCOPES_SUPPORTED) instanceof Collection<?> scopes
				&& scopes.contains(OFFLINE_ACCESS);
	}

}
