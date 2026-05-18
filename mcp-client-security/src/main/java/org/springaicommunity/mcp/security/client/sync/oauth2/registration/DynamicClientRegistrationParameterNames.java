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

/**
 * Parameter names for Dynamic Client Registration flows.
 *
 * @author Daniel Garnier-Moiroux
 */
public class DynamicClientRegistrationParameterNames {

	public static final String GRANT_TYPES = "grant_types";

	public static final String REDIRECT_URIS = "redirect_uris";

	public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";

	public static final String RESPONSE_TYPES = "response_types";

	public static final String CLIENT_NAME = "client_name";

	public static final String JWKS_URI = "jwks_uri";

	public static final String CLIENT_URI = "client_uri";

	public static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";

	public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";

	private DynamicClientRegistrationParameterNames() {

	}

}
