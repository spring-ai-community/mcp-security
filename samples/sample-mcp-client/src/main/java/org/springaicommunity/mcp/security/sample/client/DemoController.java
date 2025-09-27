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

package org.springaicommunity.mcp.security.sample.client;

import java.io.IOException;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DemoController {

	private final InMemoryMcpClientRepository mcpClientRepo;

	private ChatClient chatClient;

	DemoController(ChatClient.Builder chatClientBuilder, InMemoryMcpClientRepository mcpClientRepository) {
		this.chatClient = chatClientBuilder.build();
		this.mcpClientRepo = mcpClientRepository;
	}

	@GetMapping("/")
	String index(String query) {
		var currentWeatherBlock = "";
		if (StringUtils.hasText(query)) {
			var chatResponse = chatClient.prompt("""
					What is the weather in %s right now?
					Compare to historical data over the past 5 years.
					Format the output in plain HTML, no CSS.""".formatted(query))
				.toolCallbacks(new SyncMcpToolCallbackProvider(mcpClientRepo.getClients()))
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

		var currentMcpServersBlock = this.mcpClientRepo.getClientNames()
			.stream()
			.map("    <li>%s</li>"::formatted)
			.collect(Collectors.joining("\n"));

		return """
				<h1>Demo controller</h1>
				%s
				<h2>Ask for the weather</h2>
				<p>In which city would you like to see the weather?</p>
				<form action="" method="GET">
				    <input type="text" name="query" value="" placeholder="Paris" />
				    <button type="submit">Ask the LLM</button>
				</form>

				<h2>Registered MCP servers:</h2>
				<ul>
				%s
				</ul>
				<form action="/mcp/add" method="GET">
					<input type="text" name="name" placeholder="My MCP server" value="weather data history" />
					<input type="text" name="url" placeholder="http://localhost:8090" value="http://localhost:8090" />
					<button type="submit">Add</button>
				</form>
				""".formatted(currentWeatherBlock, currentMcpServersBlock);
	}

	// TODO: this should be a POST but that won't work with Spring Security
	@GetMapping("/mcp/add")
	void addMcpServer(@RequestParam String url, @RequestParam String name, HttpServletResponse response)
			throws IOException {
		this.mcpClientRepo.addSseClient(url, name);
		response.sendRedirect("/");
	}

}
