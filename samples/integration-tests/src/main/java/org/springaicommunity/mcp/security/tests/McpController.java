package org.springaicommunity.mcp.security.tests;

import io.modelcontextprotocol.spec.McpSchema;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class McpController {

	private final InMemoryMcpClientRepository repository;

	McpController(InMemoryMcpClientRepository repository) {
		this.repository = repository;
	}

	@GetMapping("/tool/call")
	public String callServer(String clientName, String toolName) {
		var toolResponse = ((McpSchema.TextContent) this.repository.getClientByName(clientName)
			.callTool(McpSchema.CallToolRequest.builder().name(toolName).build())
			.content()
			.get(0)).text();
		return "Called [client: %s, tool: %s], got response [%s]".formatted(clientName, toolName, toolResponse);
	}

}
