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

/**
 * The names of the claims a Resource Server describes about its configuration, used in
 * OAuth 2.0 Protected Resource Metadata.
 *
 * @author Joe Grandja
 * @see OAuth2ProtectedResourceMetadata
 */
public final class OAuth2ProtectedResourceMetadataClaimNames {

	public static final String RESOURCE = "resource";

	public static final String AUTHORIZATION_SERVERS = "authorization_servers";

	public static final String SCOPES_SUPPORTED = "scopes_supported";

	public static final String BEARER_METHODS_SUPPORTED = "bearer_methods_supported";

	public static final String RESOURCE_NAME = "resource_name";

	private OAuth2ProtectedResourceMetadataClaimNames() {
	}

}
