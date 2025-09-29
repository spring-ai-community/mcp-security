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

import io.modelcontextprotocol.spec.McpSchema;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class McpController {

	private final InMemoryMcpClientRepository repository;

	McpController(InMemoryMcpClientRepository repository) {
		this.repository = repository;
	}

	@GetMapping("/tool/call")
	public String callTool(String clientName, String toolName) {
		var toolResponse = ((McpSchema.TextContent) this.repository.getClientByName(clientName)
			.callTool(McpSchema.CallToolRequest.builder().name(toolName).build())
			.content()
			.get(0)).text();
		return "Called [client: %s, tool: %s], got response [%s]".formatted(clientName, toolName, toolResponse);
	}

}
