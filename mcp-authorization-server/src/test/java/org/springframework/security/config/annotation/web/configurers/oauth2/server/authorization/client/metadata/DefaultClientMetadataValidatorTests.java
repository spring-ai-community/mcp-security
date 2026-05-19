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

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.test.util.ReflectionTestUtils;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

/**
 * Tests for {@link DefaultClientMetadataValidator}.
 *
 * @author Daniel Garnier-Moiroux
 */
class DefaultClientMetadataValidatorTests {

	private final DefaultClientMetadataValidator validator = new DefaultClientMetadataValidator();

	private final OAuth2ClientRegistration validClient = OAuth2ClientRegistration.builder()
		.clientId("https://example.com/registration/client-id-metadata.json")
		.redirectUri("https://example.com/callback")
		.build();

	@Nested
	class Valid {

		@Test
		void valid() {
			assertThatNoException().isThrownBy(
					() -> validator.validate("https://example.com/registration/client-id-metadata.json", validClient));

		}

		@ParameterizedTest
		@ValueSource(strings = { "none", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth" })
		void tokenEndpointAuthMethod(String authMethod) {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.tokenEndpointAuthenticationMethod(authMethod)
				.build();

			assertThatNoException().isThrownBy(() -> validator
				.validate("https://example.com/registration/client-id-metadata.json", clientRegistration));

		}

	}

	@Nested
	class Invalid {

		@Test
		void emptyClientId() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.clientId("")
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("client_id");
				});
		}

		@Test
		void clientIdMismatch() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.clientId("https://example.com/other-client")
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("client_id");
				});

		}

		@Test
		void clientSecretPresent() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.clientSecret("secret")
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("client_secret");
				});

		}

		@Test
		void clientSecretExpiresAtPresent() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.clientSecret("secret")
				.clientSecretExpiresAt(Instant.now())
				.build();

			// hack to remove "client_secret" from the claims
			HashMap<String, Object> claims = new java.util.HashMap<>(clientRegistration.getClaims());
			claims.remove("client_secret");
			ReflectionTestUtils.setField(clientRegistration, "claims", Collections.unmodifiableMap(claims));

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("client_secret_expires_at");
				});

		}

		@Test
		void emptyRedirectUris() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("https://example.com/registration/client-id-metadata.json")
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("redirect_uris");
				});

		}

		@Test
		void tokenEndpointAuthMethod() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.withClaims(validClient.getClaims())
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("token_endpoint_auth_method");
				});

		}

		@Test
		void invalidRedirectUri() {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("https://example.com/registration/client-id-metadata.json")
				.redirectUri("http://example.com")
				.build();

			assertThatThrownBy(() -> validator.validate("https://example.com/registration/client-id-metadata.json",
					clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("redirect_uris");
					assertThat(e.getCause()).isInstanceOf(InvalidUrlException.class);
				});

		}

		@Test
		void invalidRedirectUriWithCustomValidator() {
			DefaultClientMetadataValidator customValidator = new DefaultClientMetadataValidator((url) -> {
				throw new InvalidUrlException("Custom validator failed", url.toString());
			});

			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("https://example.com/registration/client-id-metadata.json")
				.redirectUri("https://example.com/callback")
				.build();

			assertThatThrownBy(() -> customValidator
				.validate("https://example.com/registration/client-id-metadata.json", clientRegistration))
				.isInstanceOf(InvalidClientMetadataException.class)
				.asInstanceOf(type(InvalidClientMetadataException.class))
				.satisfies(e -> {
					assertThat(e.getClientId()).isEqualTo("https://example.com/registration/client-id-metadata.json");
					assertThat(e.getField()).isEqualTo("redirect_uris");
					assertThat(e.getCause()).isInstanceOf(InvalidUrlException.class)
						.hasMessage("Custom validator failed");
				});
		}

	}

}
