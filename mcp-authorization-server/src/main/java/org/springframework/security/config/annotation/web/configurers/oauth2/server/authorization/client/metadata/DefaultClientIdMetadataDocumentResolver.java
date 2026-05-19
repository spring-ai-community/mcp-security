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

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.web.client.RestClient;

/**
 * Resolve Client ID Metadata from a {@code client_id} URL.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public final class DefaultClientIdMetadataDocumentResolver implements ClientIdMetadataDocumentResolver {

	private static final long DEFAULT_CACHE_MAX_AGE_SECONDS = 300; // 5 minutes

	private static final long CACHE_MAX_AGE_SECONDS = 86400; // 24 hours

	private static final Pattern MAX_AGE_PATTERN = Pattern.compile("\\bmax-age=(\\d+)\\b", Pattern.CASE_INSENSITIVE);

	private final RestClient restClient;

	public DefaultClientIdMetadataDocumentResolver() {
		this(RestClient.builder()
			.configureMessageConverters((messageConverters) -> messageConverters
				.addCustomConverter(new OAuth2ClientRegistrationHttpMessageConverter()))
			.build());
	}

	public DefaultClientIdMetadataDocumentResolver(RestClient restClient) {
		this.restClient = restClient;
	}

	@Override
	public Result resolve(URI clientId) throws InvalidClientMetadataException {
		return retrieve(clientId);
	}

	private Result retrieve(URI clientId) throws InvalidClientMetadataException {
		ResponseEntity<OAuth2ClientRegistration> response = this.restClient.get()
			.uri(clientId)
			.retrieve()
			.toEntity(OAuth2ClientRegistration.class);
		OAuth2ClientRegistration clientRegistration = response.getBody();
		if (clientRegistration == null) {
			throw new InvalidClientMetadataException("Client metadata response must not have an empty body",
					clientId.toString());
		}
		long cacheMaxAgeSeconds = getMaxAgeSeconds(response.getHeaders());
		ResponseAttributes responseAttributes = new ResponseAttributes(cacheMaxAgeSeconds);
		return new Result(clientRegistration, responseAttributes);
	}

	private static long getMaxAgeSeconds(HttpHeaders headers) {
		String cacheControl = headers.getFirst(HttpHeaders.CACHE_CONTROL);
		if (cacheControl != null) {
			if (cacheControl.toLowerCase().contains("no-store")) {
				return -1;
			}
			Matcher matcher = MAX_AGE_PATTERN.matcher(cacheControl);
			if (matcher.find()) {
				long maxAge = Long.parseLong(matcher.group(1));
				if (maxAge <= 0) {
					return -1;
				}
				return Math.min(maxAge, CACHE_MAX_AGE_SECONDS);
			}
		}
		return DEFAULT_CACHE_MAX_AGE_SECONDS;
	}

}
