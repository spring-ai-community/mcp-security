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

import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Daniel Garnier-Moiroux
 */
class InMemoryMcpSessionBindingRepositoryTests {

	private final InMemoryMcpSessionBindingRepository repository = new InMemoryMcpSessionBindingRepository();

	@Test
	void findSessionBindingId() throws InvalidMcpSessionBindingException {
		this.repository.bindSession("session1", "user1");
		assertThat(this.repository.findSessionBindingId("session1")).isEqualTo("user1");
	}

	@Test
	void findSessionBindingIdNoBinding() {
		assertThat(this.repository.findSessionBindingId("unknown")).isNull();
	}

	@Test
	void bindSessionWhenAlreadyExistsThrowsException() throws InvalidMcpSessionBindingException {
		this.repository.bindSession("session1", "user1");
		assertThatThrownBy(() -> this.repository.bindSession("session1", "user2"))
			.isInstanceOf(InvalidMcpSessionBindingException.class)
			.hasMessageContaining("Session binding already exists");
	}

	@Test
	void findSessionBindingIdExpired() throws InterruptedException, InvalidMcpSessionBindingException {
		this.repository.setSessionTimeout(Duration.ofMillis(50));
		this.repository.bindSession("session1", "user1");
		assertThat(this.repository.findSessionBindingId("session1")).isNotNull();

		Awaitility.await()
			.pollDelay(Duration.ofMillis(50))
			.atMost(Duration.ofMillis(500))
			.pollInterval(Duration.ofMillis(50))
			.untilAsserted(() -> assertThat(this.repository.findSessionBindingId("session1")).isNull());
	}

	@Test
	void bindSessionExpiredSession() throws InterruptedException, InvalidMcpSessionBindingException {
		this.repository.setSessionTimeout(Duration.ofMillis(50));
		this.repository.bindSession("session1", "user1");
		assertThat(this.repository.findSessionBindingId("session1")).isNotNull();

		// This is not a real use-case as sessions IDs MUST be random ; you can't re-bind
		Awaitility.await()
			.pollDelay(Duration.ofMillis(50))
			.atMost(Duration.ofMillis(500))
			.pollInterval(Duration.ofMillis(50))
			.untilAsserted(() -> assertThat(this.repository.findSessionBindingId("session1")).isNull());
		assertThatNoException().isThrownBy(() -> this.repository.bindSession("session1", "user2"));
	}

}
