package org.springaicommunity.mcp.security.tests;

import io.modelcontextprotocol.modern.McpSchema;

import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Calls tools with MCP clients for the 2026-07-28 ("modern") protocol. Counterpart of
 * {@link McpController} for legacy clients.
 *
 * @author Daniel Garnier-Moiroux
 */
@RestController
public class ModernMcpController {

	private final InMemoryModernMcpClientRepository repository;

	ModernMcpController(InMemoryModernMcpClientRepository repository) {
		this.repository = repository;
	}

	@GetMapping("/modern/tool/call")
	public String callTool(String clientName, String toolName) {
		var client = this.repository.getClientByName(clientName);
		Assert.notNull(client, () -> "No modern MCP client named [%s]".formatted(clientName));
		var toolResponse = ((McpSchema.TextContent) client.tool(toolName).call().content().get(0)).text();
		return "Called [client: %s, tool: %s], got response [%s]".formatted(clientName, toolName, toolResponse);
	}

}
