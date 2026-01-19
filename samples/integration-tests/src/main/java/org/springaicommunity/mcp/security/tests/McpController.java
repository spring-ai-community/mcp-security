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

package org.springaicommunity.mcp.security.tests;

import java.util.Optional;

import io.modelcontextprotocol.spec.McpSchema;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import reactor.core.publisher.Mono;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Daniel Garnier-Moiroux
 */
@RestController
public class McpController {

	private final InMemoryMcpClientRepository repository;

	// Not all tests have ChatClient support, so we wrap it in a supplier that will
	// only be used in LLM-powered tests.
	private final SingletonSupplier<ChatClient> chatClientSupplier;

	McpController(InMemoryMcpClientRepository repository, ObjectProvider<ChatClient.Builder> chatClientBuilder,
			Optional<SyncMcpToolCallbackProvider> mcpTools) {
		this.repository = repository;
		this.chatClientSupplier = SingletonSupplier
			.of(() -> chatClientBuilder.getIfUnique().defaultToolCallbacks(mcpTools.get()).build());
	}

	@GetMapping("/tool/call")
	public String callTool(String clientName, String toolName) {
		var toolResponse = ((McpSchema.TextContent) this.repository.getClientByName(clientName)
			.callTool(McpSchema.CallToolRequest.builder().name(toolName).build())
			.content()
			.get(0)).text();
		return "Called [client: %s, tool: %s], got response [%s]".formatted(clientName, toolName, toolResponse);
	}

	@GetMapping("/chat")
	public String chat(String question) {
		return chatClientSupplier.get().prompt(question).call().content();
	}

	@GetMapping("/stream")
	public String stream(String question) {
		return chatClientSupplier.get()
			.prompt(question)
			.stream()
			.content()
			.contextWrite(AuthenticationMcpTransportContextProvider.writeToReactorContext())
			.blockLast();
	}

	@GetMapping("/stream-no-context")
	public String streamNoContext(String question) {
		return chatClientSupplier.get().prompt(question).stream().content().blockLast();
	}

}
