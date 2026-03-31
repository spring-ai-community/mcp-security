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

package org.springaicommunity.mcp.security.client.boot;

import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Configuration properties for MCP OAuth2 Client.
 *
 * @author Daniel Garnier-Moiroux
 */
@ConfigurationProperties(McpOAuth2ClientProperties.CONFIG_PREFIX)
public class McpOAuth2ClientProperties {

	public static final String CONFIG_PREFIX = "spring.ai.mcp.client.authorization";

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
		 * <p>
		 * If false, ensure you either have a single {@link ClientRegistration} registered
		 * under {@code spring.security.oauth2.client.registration}, or you provide your
		 * own {@link OAuth2HttpClientTransportCustomizer} bean.
		 */
		private boolean enabled = false;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

}
