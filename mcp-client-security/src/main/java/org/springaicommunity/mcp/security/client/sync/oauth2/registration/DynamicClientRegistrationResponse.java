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

import java.time.Instant;
import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * Represents the response for OAuth2 Dynamic Client registration request.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1">RFC7591 -
 * 3.2.1 Client information response</a>
 */
public record DynamicClientRegistrationResponse(
		// Required
		String clientId,
		// Optional credentials
		@Nullable String clientSecret, @Nullable Instant clientIdIssuedAt, @Nullable Instant clientSecretExpiresAt,
		// Client metadata (Section 2)
		@Nullable List<String> redirectUris, @Nullable String tokenEndpointAuthMethod,
		@Nullable List<String> grantTypes, @Nullable List<String> responseTypes, @Nullable String clientName,
		@Nullable String scope, @Nullable String jwksUri) {
}
