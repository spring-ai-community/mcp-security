package org.springaicommunity.mcp.security.tests;

import io.modelcontextprotocol.client.McpSyncClient;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;

public class InMemoryMcpClientRepository {

	private final Map<String, McpSyncClient> clients = new HashMap<>();

	public InMemoryMcpClientRepository(List<McpSyncClient> clients, McpClientCommonProperties commonProperties) {
		for (var client : clients) {
			var name = client.getClientInfo().name();
			this.clients.putIfAbsent(name.replace(commonProperties.getName() + " - ", ""), client);
		}
	}

	public McpSyncClient getClientByName(String name) {
		return this.clients.get(name);
	}

	public void addClient(String name, McpSyncClient client) {
		this.clients.put(name, client);
	}

}
