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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * In-memory implementation of {@link McpSessionBindingRepository}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryMcpSessionBindingRepository implements McpSessionBindingRepository {

	private final Map<String, SessionBinding> bindings = new ConcurrentHashMap<>();

	private Duration sessionTimeout = Duration.ofHours(48);

	@Override
	@Nullable public String findSessionBindingId(String sessionId) {
		SessionBinding binding = this.bindings.get(sessionId);
		if (binding == null) {
			return null;
		}

		if (isExpired(binding, Instant.now())) {
			this.bindings.remove(sessionId);
			return null;
		}

		binding.setLastAccessedTime(Instant.now());
		return binding.getUserId();
	}

	@Override
	public void bindSession(String sessionId, String sessionBindingId) throws InvalidMcpSessionBindingException {
		Assert.notNull(sessionId, "sessionId cannot be null");
		Assert.notNull(sessionBindingId, "userId cannot be null");

		cleanUpExpiredSessions();

		// This should NEVER happen, as you should only ever bind user ID to new sessions
		SessionBinding existing = this.bindings.putIfAbsent(sessionId,
				new SessionBinding(sessionBindingId, Instant.now()));
		if (existing != null) {
			throw new InvalidMcpSessionBindingException("Session binding already exists for session ID: " + sessionId);
		}
	}

	/**
	 * Sets the session timeout duration.
	 * @param sessionTimeout the session timeout
	 */
	public void setSessionTimeout(Duration sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}

	private void cleanUpExpiredSessions() {
		Instant now = Instant.now();
		this.bindings.entrySet().removeIf(entry -> isExpired(entry.getValue(), now));
	}

	private boolean isExpired(SessionBinding binding, Instant now) {
		return now.isAfter(binding.getLastAccessedTime().plus(this.sessionTimeout));
	}

	private static final class SessionBinding {

		private final String userId;

		private volatile Instant lastAccessedTime;

		private SessionBinding(String userId, Instant lastAccessedTime) {
			this.userId = userId;
			this.lastAccessedTime = lastAccessedTime;
		}

		public String getUserId() {
			return this.userId;
		}

		public Instant getLastAccessedTime() {
			return this.lastAccessedTime;
		}

		public void setLastAccessedTime(Instant lastAccessedTime) {
			this.lastAccessedTime = lastAccessedTime;
		}

	}

}
