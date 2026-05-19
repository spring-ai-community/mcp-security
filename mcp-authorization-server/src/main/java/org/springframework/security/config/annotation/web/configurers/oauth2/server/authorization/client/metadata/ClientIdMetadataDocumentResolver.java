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

import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;

/**
 * Resolve Client ID Metadata from a {@code client_id} URL.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">OAuth
 * Client ID Metadata Document</a>
 *
 */
public interface ClientIdMetadataDocumentResolver {

	/**
	 * Resolve client metadata from a {@code client_id} URI. The uri MUST be a trusted
	 * URI.
	 * @param clientId the client_id URI
	 * @return the Metadata response
	 * @throws InvalidClientMetadataException when no metadata is fetched from that URI
	 * @see ClientIdUrlValidator
	 */
	Result resolve(URI clientId) throws InvalidClientMetadataException;

	record Result(OAuth2ClientRegistration clientRegistration, ResponseAttributes responseAttributes) {
	}

	record ResponseAttributes(long cacheMaxAgeSeconds) {
	}

}
