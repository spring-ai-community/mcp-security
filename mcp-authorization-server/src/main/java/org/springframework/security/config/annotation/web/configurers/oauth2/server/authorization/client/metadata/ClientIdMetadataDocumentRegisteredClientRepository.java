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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.util.Assert;

/**
 * A {@link RegisteredClientRepository} for Client ID Metadata Document-based OAuth2
 * clients. Clients make requests to the server using a URL as their {@code client_id},
 * and the server resolves metadata based on that URL.
 * <p>
 * Implementations MUST validate both the client ID url and metadata through custom
 * {@link ClientMetadataValidator} and {@link ClientIdMetadataDocumentResolver}.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">OAuth
 * Client ID Metadata Document</a>
 * @see org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.DelegatingRegisteredClientRepository
 */
public final class ClientIdMetadataDocumentRegisteredClientRepository implements RegisteredClientRepository {

	private static final Logger log = LoggerFactory.getLogger(ClientIdMetadataDocumentRegisteredClientRepository.class);

	private final Cache cache = new Cache();

	private Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter = new OAuth2ClientRegistrationRegisteredClientConverter();

	private ClientIdMetadataDocumentResolver metadataDocumentResolver = new DefaultClientIdMetadataDocumentResolver();

	private ClientMetadataValidator metadataValidator = new DefaultClientMetadataValidator();

	private UrlValidator urlValidator = new ClientIdUrlValidator();

	@Override
	public void save(RegisteredClient registeredClient) {
		// No-op
	}

	@Override
	@Nullable public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.cache.getById(id);
	}

	@Override
	@Nullable public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		RegisteredClient cachedRegisteredClient = this.cache.getByClientId(clientId);
		if (cachedRegisteredClient != null) {
			return cachedRegisteredClient;
		}
		URI clientIdUri;
		try {
			clientIdUri = URI.create(clientId);
		}
		catch (IllegalArgumentException e) {
			log.debug("Client id [{}] is not a valid HTTP(s) URI, skipping", clientId);
			return null;
		}
		if (clientIdUri.getScheme() == null || !clientIdUri.getScheme().startsWith("http")) {
			log.debug("Client id [{}] is not a valid HTTP(s) URI, skipping", clientId);
			return null;
		}
		ClientIdMetadataDocumentResolver.Result result = null;
		try {
			this.urlValidator.validateUrl(clientIdUri);
		}
		catch (InvalidUrlException e) {
			throw new IllegalArgumentException(e);
		}
		try {
			result = this.metadataDocumentResolver.resolve(clientIdUri);
		}
		catch (InvalidClientMetadataException e) {
			throw new IllegalArgumentException(e);
		}
		OAuth2ClientRegistration clientRegistration = result.clientRegistration();
		try {
			this.metadataValidator.validate(clientId, clientRegistration);
		}
		catch (InvalidClientMetadataException e) {
			log.error("Invalid client metadata for client with id [%s]".formatted(clientId), e);
			throw new IllegalArgumentException("Invalid client metadata for client with id [%s]".formatted(clientId),
					e);
		}
		RegisteredClient registeredClient = this.registeredClientConverter.convert(clientRegistration);
		registeredClient = RegisteredClient.from(registeredClient).id(clientId).clientId(clientId).build();
		if (result.responseAttributes().cacheMaxAgeSeconds() >= 0) {
			long cacheMaxAgeSeconds = result.responseAttributes().cacheMaxAgeSeconds();
			this.cache.put(registeredClient, System.currentTimeMillis() + cacheMaxAgeSeconds * 1000);
		}
		return registeredClient;
	}

	/**
	 * Set the converter used to transform client metadata to {@link RegisteredClient}.
	 * @param registeredClientConverter the converter
	 */
	public void setRegisteredClientConverter(
			Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter) {
		Assert.notNull(registeredClientConverter, "registeredClientConverter cannot be null");
		this.registeredClientConverter = registeredClientConverter;
	}

	/**
	 * Set the resolver used to fetch the metadata document for a given client ID.l
	 * @param metadataDocumentResolver the resolver
	 */
	public void setMetadataDocumentResolver(ClientIdMetadataDocumentResolver metadataDocumentResolver) {
		Assert.notNull(metadataDocumentResolver, "metadataDocumentResolver cannot be null");
		this.metadataDocumentResolver = metadataDocumentResolver;
	}

	/**
	 * Set the validator used to validate the client metadata before storing the client.
	 * @param metadataValidator the validator
	 */
	public void setMetadataValidator(ClientMetadataValidator metadataValidator) {
		Assert.notNull(metadataValidator, "metadataValidator cannot be null");
		this.metadataValidator = metadataValidator;
	}

	/**
	 * Set the validator used to validate the {@code client_id} URL before requesting
	 * metadata from that URL.l
	 * @param urlValidator the validator
	 */
	public void setClientIdUrlValidator(UrlValidator urlValidator) {
		Assert.notNull(urlValidator, "urlValidator cannot be null");
		this.urlValidator = urlValidator;
	}

	private static final class Cache {

		private final Map<String, CacheEntry> clientIdToEntry = new ConcurrentHashMap<>();

		private final Map<String, CacheEntry> idToEntry = new ConcurrentHashMap<>();

		@Nullable private RegisteredClient getById(String id) {
			Assert.hasText(id, "id cannot be empty");
			CacheEntry cacheEntry = this.idToEntry.get(id);
			if (cacheEntry == null) {
				return null;
			}
			if (cacheEntry.isExpired()) {
				evict(cacheEntry.registeredClient);
				return null;
			}
			return cacheEntry.registeredClient;
		}

		@Nullable private RegisteredClient getByClientId(String clientId) {
			Assert.hasText(clientId, "clientId cannot be empty");
			CacheEntry cacheEntry = this.clientIdToEntry.get(clientId);
			if (cacheEntry == null) {
				return null;
			}
			if (cacheEntry.isExpired()) {
				evict(cacheEntry.registeredClient);
				return null;
			}
			return cacheEntry.registeredClient;
		}

		private void put(RegisteredClient registeredClient, long expiryMillis) {
			CacheEntry cacheEntry = new CacheEntry(registeredClient, expiryMillis);
			this.clientIdToEntry.put(registeredClient.getClientId(), cacheEntry);
			this.idToEntry.put(registeredClient.getId(), cacheEntry);
		}

		private void evict(RegisteredClient registeredClient) {
			this.clientIdToEntry.remove(registeredClient.getClientId());
			this.idToEntry.remove(registeredClient.getId());
		}

		private record CacheEntry(RegisteredClient registeredClient, long expiryMillis) {

			boolean isExpired() {
				return System.currentTimeMillis() > this.expiryMillis;
			}

		}

	}

}
