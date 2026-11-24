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

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.function.Consumer;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

/**
 * Post-processor to customize the {@link TokenSettings} of dynamically registered clients
 * on {@link OAuth2ClientRegistrationAuthenticationProvider}.
 * <p>
 * For internal use only.
 *
 * @author Mohit Gupta
 */
class McpClientRegistrationTokenSettingsPostProcessor
		implements ObjectPostProcessor<OAuth2ClientRegistrationAuthenticationProvider> {

	private final Consumer<TokenSettings.Builder> tokenSettingsCustomizer;

	McpClientRegistrationTokenSettingsPostProcessor(Consumer<TokenSettings.Builder> tokenSettingsCustomizer) {
		this.tokenSettingsCustomizer = tokenSettingsCustomizer;
	}

	@Override
	public OAuth2ClientRegistrationAuthenticationProvider postProcess(
			OAuth2ClientRegistrationAuthenticationProvider object) {
		OAuth2ClientRegistrationRegisteredClientConverter converter = new OAuth2ClientRegistrationRegisteredClientConverter();
		converter.setTokenSettingsCustomizer(this.tokenSettingsCustomizer);
		object.setRegisteredClientConverter(converter);
		return object;
	}

}
