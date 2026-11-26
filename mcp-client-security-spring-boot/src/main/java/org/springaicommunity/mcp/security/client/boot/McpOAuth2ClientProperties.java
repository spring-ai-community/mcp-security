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
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern.OAuth2HttpClientMcpTransportCustomizer;

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

	/**
	 * Allow communicating with MCP Servers and Authorization Servers on loopback
	 * interfaces, including localhost, 127.0.0.1 and [::1].
	 * <p>
	 * For development use only.
	 */
	private boolean allowLoopbackAddresses = false;

	private DynamicClientRegistration dynamicClientRegistration = new DynamicClientRegistration();

	private Cimd cimd = new Cimd();

	public boolean isAllowLoopbackAddresses() {
		return allowLoopbackAddresses;
	}

	public void setAllowLoopbackAddresses(boolean allowLoopbackAddresses) {
		this.allowLoopbackAddresses = allowLoopbackAddresses;
	}

	public DynamicClientRegistration getDynamicClientRegistration() {
		return dynamicClientRegistration;
	}

	public void setDynamicClientRegistration(DynamicClientRegistration dynamicClientRegistration) {
		this.dynamicClientRegistration = dynamicClientRegistration;
	}

	public Cimd getCimd() {
		return cimd;
	}

	public void setCimd(Cimd cimd) {
		this.cimd = cimd;
	}

	public static class DynamicClientRegistration {

		private boolean enabled = false;

		public boolean isEnabled() {
			return enabled;
		}

		/**
		 * Enable dynamic client registration. Defaults to {@code false}.
		 */
		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

	}

	/**
	 * Client ID Metadata Document (CIMD) configuration.
	 */
	public static class Cimd {

		/**
		 * Enable Client ID Metadata Documents (CIMD) for client registration. Defaults to
		 * {@code true}.
		 * <p>
		 * If false, ensure one of the following is true:
		 * <ul>
		 * <li>There is a single {@link ClientRegistration} under
		 * {@code spring.security.oauth2.client.registration}</li>
		 * <li>OR {@link DynamicClientRegistration#setEnabled} is set to {@code true}</li>
		 * <li>OR you provide your own {@link OAuth2HttpClientTransportCustomizer} bean
		 * for legacy connections, or {@link OAuth2HttpClientMcpTransportCustomizer} bean
		 * for modern connections</li>
		 * </ul>
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
