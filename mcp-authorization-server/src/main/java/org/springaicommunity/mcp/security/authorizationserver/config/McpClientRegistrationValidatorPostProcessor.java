/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.function.Consumer;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;

/**
 * Post-processor to set the client registration validator on
 * {@link OAuth2ClientRegistrationAuthenticationProvider}.
 * <p>
 * For internal use only.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpClientRegistrationValidatorPostProcessor
		implements ObjectPostProcessor<OAuth2ClientRegistrationAuthenticationProvider> {

	private final Consumer<OAuth2ClientRegistrationAuthenticationContext> validator;

	McpClientRegistrationValidatorPostProcessor(Consumer<OAuth2ClientRegistrationAuthenticationContext> validator) {
		this.validator = validator;
	}

	public OAuth2ClientRegistrationAuthenticationProvider postProcess(
			OAuth2ClientRegistrationAuthenticationProvider object) {
		object.setAuthenticationValidator(validator);
		return object;
	}

}
