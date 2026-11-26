package org.springaicommunity.mcp.security.tests;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.modelcontextprotocol.modern.client.McpSyncClient;
import org.jspecify.annotations.Nullable;

/**
 * Holds MCP clients for the 2026-07-28 ("modern") protocol, by name. Counterpart of
 * {@link InMemoryMcpClientRepository} for legacy clients.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryModernMcpClientRepository {

	private final Map<String, McpSyncClient> clients = new ConcurrentHashMap<>();

	public @Nullable McpSyncClient getClientByName(String name) {
		return this.clients.get(name);
	}

	public void addClient(String name, McpSyncClient client) {
		this.clients.put(name, client);
	}

}
