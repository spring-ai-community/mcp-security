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

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/**
 * Matches when at least one client registration mechanism, CIMD or DCR, is enabled.
 *
 * @author Daniel Garnier-Moiroux
 */
class ClientRegistrationEnabledCondition extends AnyNestedCondition {

	ClientRegistrationEnabledCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "cimd.enabled",
			havingValue = "true", matchIfMissing = true)
	static class CimdEnabled {

	}

	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
			name = "dynamic-client-registration.enabled", havingValue = "true")
	static class DcrEnabled {

	}

}
