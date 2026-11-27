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

package org.springaicommunity.mcp.security.sample.client.modern;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;
import org.springframework.ai.mcp.modern.client.SyncModernMcpConnection;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DemoController {

	private final SyncMcpToolCallbackProvider mcpToolCallbacks;

	private final List<SyncModernMcpConnection> connections;

	private final ChatClient chatClient;

	/**
	 * Modern connections create their client for each request, without contacting the
	 * server at startup. The auto-configured {@link SyncMcpToolCallbackProvider} serves
	 * the tools of the modern connections, next to those of legacy clients.
	 */
	DemoController(ChatClient.Builder chatClientBuilder, SyncMcpToolCallbackProvider mcpToolCallbacks,
			List<SyncModernMcpConnection> connections) {
		this.chatClient = chatClientBuilder.build();
		this.mcpToolCallbacks = mcpToolCallbacks;
		this.connections = connections;
	}

	@GetMapping("/")
	String index(String query) {
		var currentWeatherBlock = "";
		if (StringUtils.hasText(query)) {
			var chatResponse = chatClient
				.prompt("""
						What is the current weather in %s?
						Format the output in plain HTML, no CSS (it will be embedded, unescaped, in an HTML template)."""
					.formatted(query))
				.tools(mcpToolCallbacks)
				.call()
				.content();

			currentWeatherBlock = """
					<h2>Weather in %s</h2>
					<p>%s</p>
					<form action="" method="GET">
					<button type="submit">Clear</button>
					</form>
					""".formatted(query, chatResponse);
		}

		var currentMcpServersBlock = this.connections.stream()
			.map(connection -> connection.info().name())
			.map("    <li>%s</li>"::formatted)
			.collect(Collectors.joining("\n"));

		return """
				<h1>Demo controller (modern MCP protocol)</h1>
				%s

				<hr>

				<h2>Ask for the weather</h2>
				<p>In which city would you like to see the weather?</p>
				<form action="" method="GET">
				    <input type="text" name="query" value="" placeholder="Paris" />
				    <button type="submit">Ask the LLM</button>
				</form>

				<hr>

				<h2>Registered MCP connections:</h2>
				<ul>
				%s
				</ul>
				""".formatted(currentWeatherBlock, currentMcpServersBlock);
	}

}
