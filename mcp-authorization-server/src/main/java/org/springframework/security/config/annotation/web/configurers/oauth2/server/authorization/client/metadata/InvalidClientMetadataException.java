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

import org.jspecify.annotations.Nullable;

/**
 * Exception thrown when a client's exposed metadata is invalid.
 */
public class InvalidClientMetadataException extends Exception {

	private final String clientId;

	private final @Nullable String field;

	public InvalidClientMetadataException(String clientId, String field, Throwable cause) {
		super("Invalid client metadata for [%s], field [%s]".formatted(clientId, field), cause);
		this.clientId = clientId;
		this.field = field;
	}

	public InvalidClientMetadataException(String clientId, String field) {
		this("Invalid client metadata for [%s], field [%s]".formatted(clientId, field), clientId, field);
	}

	public InvalidClientMetadataException(String message, String clientId, @Nullable String field) {
		super(message);
		this.clientId = clientId;
		this.field = field;
	}

	/**
	 * The specific field that is invalid.
	 * @return the field name
	 */
	public @Nullable String getField() {
		return field;
	}

	/**
	 * The Client ID url.
	 * @return the client_id
	 */
	public String getClientId() {
		return clientId;
	}

}
