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

package org.springaicommunity.mcp.security.server.session;

import org.jspecify.annotations.Nullable;

/**
 * Repository for managing MCP session bindings. Sessions are bound to a unique
 * identifier, typically the users' OAuth2 token {@code sub} claim.
 *
 * @author Daniel Garnier-Moiroux
 */
public interface McpSessionBindingRepository {

	/**
	 * Finds the session binding ID for the given session ID.
	 * @param sessionId the session ID
	 * @return the session binding ID, or null if not found
	 */
	@Nullable String findSessionBindingId(String sessionId);

	/**
	 * Binds the given session ID to the given session binding ID.
	 * @param sessionId the session ID
	 * @param sessionBindingId the session binding ID
	 * @throws InvalidMcpSessionBindingException if a binding already exists for this
	 * session
	 */
	void bindSession(String sessionId, String sessionBindingId) throws InvalidMcpSessionBindingException;

}
