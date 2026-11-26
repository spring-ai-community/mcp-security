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

package org.springaicommunity.mcp.security.server.config;

import java.time.Instant;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jwt.Jwt;
import static org.assertj.core.api.Assertions.assertThat;

class McpServerOAuth2ConfigurerTests {

	private static final String ISSUER = "https://example.com";

	@Test
	void acceptsJwtTokenType() {
		var result = McpServerOAuth2Configurer.createJwtValidator(ISSUER).validate(jwt("JWT"));

		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	void acceptsAtJwtTokenType() {
		var result = McpServerOAuth2Configurer.createJwtValidator(ISSUER).validate(jwt("at+jwt"));

		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	void acceptsMissingTokenType() {
		var result = McpServerOAuth2Configurer.createJwtValidator(ISSUER).validate(jwt(null));

		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	void rejectsUnsupportedTokenType() {
		var result = McpServerOAuth2Configurer.createJwtValidator(ISSUER).validate(jwt("unsupported+jwt"));

		assertThat(result.hasErrors()).isTrue();
	}

	private static Jwt jwt(@Nullable String type) {
		var now = Instant.now();
		var builder = Jwt.withTokenValue("token")
			.issuedAt(now.minusSeconds(60))
			.expiresAt(now.plusSeconds(60))
			.issuer(ISSUER)
			.header("kid", "key-id");
		if (type != null) {
			builder.header("typ", type);
		}
		return builder.build();
	}

}
