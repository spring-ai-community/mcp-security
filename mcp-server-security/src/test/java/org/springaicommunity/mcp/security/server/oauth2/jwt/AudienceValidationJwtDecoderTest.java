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

package org.springaicommunity.mcp.security.server.oauth2.jwt;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AudienceValidationJwtDecoderTest {

	private final JwtDecoder delegate = mock();

	private final ResourceIdentifier resourceIdentifier = mock();

	@BeforeEach
	void setUp() {
		when(resourceIdentifier.getResource()).thenReturn("https://example.com/mcp");
		when(delegate.decode(anyString())).thenReturn(jwt("https://example.com/mcp"));
	}

	@Test
	void valid() {
		var validator = new AudienceValidationJwtDecoder(delegate, resourceIdentifier);

		var jwt = validator.decode("~~ignored~~");

		assertThat(jwt).isEqualTo(jwt("https://example.com/mcp"));
	}

	@Test
	void invalidAudience() {
		when(delegate.decode(anyString())).thenReturn(jwt("https://example.com/incorrect-audience"));
		var validator = new AudienceValidationJwtDecoder(delegate, resourceIdentifier);

		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> validator.decode("~~ignored~~"))
			.withMessage("An error occurred while attempting to decode the Jwt: The aud claim is not valid");
	}

	@Test
	void invalidToken() {
		when(delegate.decode(anyString())).thenThrow(new BadJwtException("cannot decode jwt"));

		var validator = new AudienceValidationJwtDecoder(delegate, resourceIdentifier);

		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> validator.decode("~~ignored~~"))
			.withMessage("cannot decode jwt");
	}

	private static Jwt jwt(String audience) {
		return Jwt.withTokenValue("~~~ignored~~~")
			.header("kid", "~~~ignored~~")
			.claim("aud", List.of(audience))
			.build();
	}

}
