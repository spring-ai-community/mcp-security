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

import java.util.HashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2DcrHttpClientTransportCustomizer;

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

	private final Map<String, Registration> registration = new HashMap<>();

	public DynamicClientRegistration getDynamicClientRegistration() {
		return dynamicClientRegistration;
	}

	public void setDynamicClientRegistration(DynamicClientRegistration dynamicClientRegistration) {
		this.dynamicClientRegistration = dynamicClientRegistration;
	}

	public Map<String, Registration> getRegistration() {
		return this.registration;
	}

	public static class Registration {

		/**
		 * RFC 8707 {@code resource} identifier (typically the MCP server URL) to attach
		 * to authorization and token requests for this client registration.
		 */
		private @Nullable String resource;

		public @Nullable String getResource() {
			return this.resource;
		}

		public void setResource(@Nullable String resource) {
			this.resource = resource;
		}

	}

	public static class DynamicClientRegistration {

		/**
		 * Enable dynamic client registration.
		 * <p>
		 * If false, ensure you either have a single {@link ClientRegistration} registered
		 * under {@code spring.security.oauth2.client.registration}, or you provide your
		 * own {@link OAuth2DcrHttpClientTransportCustomizer} bean.
		 */
		private boolean enabled = false;

		/**
		 * Allow communicating with MCP Servers and Authorization Servers on loopback
		 * interfaces, including localhost, 127.0.0.1 and [::1].
		 * <p>
		 * For development use only.
		 */
		private boolean allowLoopbackAddresses = false;

		public boolean isAllowLoopbackAddresses() {
			return allowLoopbackAddresses;
		}

		public void setAllowLoopbackAddresses(boolean allowLoopbackAddresses) {
			this.allowLoopbackAddresses = allowLoopbackAddresses;
		}

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

}
