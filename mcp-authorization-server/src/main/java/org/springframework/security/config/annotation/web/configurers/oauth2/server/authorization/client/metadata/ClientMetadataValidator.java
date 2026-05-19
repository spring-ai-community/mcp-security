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

import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;

/**
 * Validate Client ID Metadata obtained from an OAuth2 client.
 *
 * @see <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">OAuth
 * Client ID Metadata Document</a>
 */
public interface ClientMetadataValidator {

	/**
	 * Validate metadata fetched for a CIMD client.
	 * @param clientIdUrl the client ID
	 * @param metadata the client metadata
	 */
	void validate(String clientIdUrl, OAuth2ClientRegistration metadata) throws InvalidClientMetadataException;

}
