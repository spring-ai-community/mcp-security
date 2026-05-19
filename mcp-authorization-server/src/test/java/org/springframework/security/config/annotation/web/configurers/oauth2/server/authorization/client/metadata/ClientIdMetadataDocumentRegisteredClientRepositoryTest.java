/*
 * Copyright 2020-2026 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ClientIdMetadataDocumentRegisteredClientRepository}.
 */
class ClientIdMetadataDocumentRegisteredClientRepositoryTest {

	private final ClientIdMetadataDocumentRegisteredClientRepository repository = new ClientIdMetadataDocumentRegisteredClientRepository();

	private final ClientIdMetadataDocumentResolver metadataDocumentResolver = mock(
			ClientIdMetadataDocumentResolver.class);

	private final ClientMetadataValidator metadataValidator = mock(ClientMetadataValidator.class);

	private final UrlValidator urlValidator = mock(UrlValidator.class);

	private final Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter = mock(
			Converter.class);

	@BeforeEach
	void setUp() {
		this.repository.setMetadataDocumentResolver(this.metadataDocumentResolver);
		this.repository.setMetadataValidator(this.metadataValidator);
		this.repository.setClientIdUrlValidator(this.urlValidator);
		this.repository.setRegisteredClientConverter(this.registeredClientConverter);
	}

	@Test
	void saveNoop() {
		RegisteredClient registeredClient = RegisteredClient.withId("id")
			.clientId("client-id")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.redirectUri("https://example.com/callback")
			.build();
		this.repository.save(registeredClient);
		assertThat(this.repository.findById("id")).isNull();
	}

	@Nested
	class FindById {

		@Test
		void findByIdWhenIdEmptyThenThrowIllegalArgumentException() {
			assertThatIllegalArgumentException().isThrownBy(() -> repository.findById(""))
				.withMessage("id cannot be empty");
		}

		@Test
		void findByIdWhenNotInCacheThenReturnNull() {
			assertThat(repository.findById("id")).isNull();
		}

	}

	@Nested
	class FindByClientId {

		@Nested
		class Valid {

			private final String clientId = "https://example.com";

			private final RegisteredClient client = RegisteredClient.withId("id")
				.clientId(clientId)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://example.com/callback")
				.build();

			private final OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId(clientId)
				.build();

			@BeforeEach
			void setUp() {
				when(registeredClientConverter.convert(clientRegistration)).thenReturn(client);
			}

			@Test
			void notCached() throws Exception {
				ClientIdMetadataDocumentResolver.Result result = new ClientIdMetadataDocumentResolver.Result(
						clientRegistration, new ClientIdMetadataDocumentResolver.ResponseAttributes(-1));
				when(metadataDocumentResolver.resolve(any(URI.class))).thenReturn(result);

				RegisteredClient resultClient = repository.findByClientId(clientId);

				assertThat(resultClient).isNotNull();
				assertThat(resultClient.getId()).isEqualTo(clientId);
				assertThat(resultClient.getClientId()).isEqualTo(clientId);

				// Verify it was not cached
				assertThat(repository.findById(clientId)).isNull();
				repository.findByClientId(clientId);
				verify(metadataDocumentResolver, times(2)).resolve(any(URI.class));
			}

			@Test
			void cached() throws Exception {
				ClientIdMetadataDocumentResolver.Result result = new ClientIdMetadataDocumentResolver.Result(
						clientRegistration, new ClientIdMetadataDocumentResolver.ResponseAttributes(60));
				when(metadataDocumentResolver.resolve(any(URI.class))).thenReturn(result);

				RegisteredClient resultClient = repository.findByClientId(clientId);

				assertThat(resultClient).isNotNull();
				assertThat(resultClient.getId()).isEqualTo(clientId);
				assertThat(resultClient.getClientId()).isEqualTo(clientId);

				// Verify it was cached
				assertThat(repository.findById(clientId)).isNotNull();
				assertThat(repository.findByClientId(clientId)).isNotNull();
				verify(metadataDocumentResolver).resolve(any(URI.class));
			}

			@Test
			void cacheExpiredThenEvictAndResolveAgain() throws Exception {
				// Cache for 0 seconds (expires immediately)
				ClientIdMetadataDocumentResolver.Result result = new ClientIdMetadataDocumentResolver.Result(
						clientRegistration, new ClientIdMetadataDocumentResolver.ResponseAttributes(0));
				when(metadataDocumentResolver.resolve(any(URI.class))).thenReturn(result);

				RegisteredClient resultClient = repository.findByClientId(clientId);
				assertThat(resultClient).isNotNull();

				// Wait a bit to ensure it's expired
				Thread.sleep(10);

				// Verify it was evicted and not found by ID
				assertThat(repository.findById(clientId)).isNull();
				repository.findByClientId(clientId);
				verify(metadataDocumentResolver, times(2)).resolve(any(URI.class));
			}

		}

		@Nested
		class Invalid {

			@Test
			void clientIdEmptyThenThrowIllegalArgumentException() {
				assertThatIllegalArgumentException().isThrownBy(() -> repository.findByClientId(""))
					.withMessage("clientId cannot be empty");
			}

			@Test
			void invalidUriThenReturnNull() {
				assertThat(repository.findByClientId("not a uri")).isNull();
			}

		}

		@Test
		void invalidUrlExceptionThenThrowIllegalArgumentException() throws Exception {
			doThrow(new InvalidUrlException("https://example.com", "invalid")).when(urlValidator)
				.validateUrl(any(URI.class));
			assertThatIllegalArgumentException().isThrownBy(() -> repository.findByClientId("https://example.com"))
				.withCauseInstanceOf(InvalidUrlException.class);
		}

		@Test
		void resolverThrowsInvalidClientMetadataExceptionThenThrowIllegalArgumentException() throws Exception {
			doThrow(new InvalidClientMetadataException("https://example.com", "invalid")).when(metadataDocumentResolver)
				.resolve(any(URI.class));
			assertThatIllegalArgumentException().isThrownBy(() -> repository.findByClientId("https://example.com"))
				.withCauseInstanceOf(InvalidClientMetadataException.class)
				.withMessageContaining("Invalid client metadata for [https://example.com]");
		}

		@Test
		void validatorThrowsInvalidClientMetadataExceptionThenThrowIllegalArgumentException() throws Exception {
			OAuth2ClientRegistration clientRegistration = OAuth2ClientRegistration.builder()
				.clientId("https://example.com")
				.build();
			ClientIdMetadataDocumentResolver.Result result = new ClientIdMetadataDocumentResolver.Result(
					clientRegistration, new ClientIdMetadataDocumentResolver.ResponseAttributes(-1));
			when(metadataDocumentResolver.resolve(any(URI.class))).thenReturn(result);
			doThrow(new InvalidClientMetadataException("invalid_client_metadata", "invalid")).when(metadataValidator)
				.validate(eq("https://example.com"), eq(clientRegistration));

			assertThatIllegalArgumentException().isThrownBy(() -> repository.findByClientId("https://example.com"))
				.withMessageContaining("Invalid client metadata for client with id [https://example.com]")
				.withCauseInstanceOf(InvalidClientMetadataException.class);
		}

	}

}
