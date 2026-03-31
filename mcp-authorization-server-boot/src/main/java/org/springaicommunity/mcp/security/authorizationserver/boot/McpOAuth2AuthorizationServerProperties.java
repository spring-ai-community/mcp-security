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

package org.springaicommunity.mcp.security.authorizationserver.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Daniel Garnier-Moiroux
 */
@ConfigurationProperties(value = McpOAuth2AuthorizationServerProperties.CONFIG_PREFIX)
class McpOAuth2AuthorizationServerProperties {

	public static final String CONFIG_PREFIX = "spring.ai.mcp.authorizationserver";

	private DynamicClientRegistration dynamicClientRegistration = new DynamicClientRegistration();

	public DynamicClientRegistration getDynamicClientRegistration() {
		return dynamicClientRegistration;
	}

	public void setDynamicClientRegistration(DynamicClientRegistration dynamicClientRegistration) {
		this.dynamicClientRegistration = dynamicClientRegistration;
	}

	public static class DynamicClientRegistration {

		/**
		 * Enable dynamic client registration.
		 */
		private boolean enabled = true;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

}
