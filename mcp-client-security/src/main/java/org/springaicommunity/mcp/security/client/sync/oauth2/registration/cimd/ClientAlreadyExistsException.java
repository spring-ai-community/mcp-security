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
package org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd;

/**
 * Thrown when a CIMD client already exists in the registration repository.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ClientAlreadyExistsException extends Exception {

	private final String registrationId;

	public ClientAlreadyExistsException(String registrationId) {
		super("Client with registration id [%s] already exists".formatted(registrationId));
		this.registrationId = registrationId;
	}

	public String getRegistrationId() {
		return registrationId;
	}

}
