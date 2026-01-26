package org.springaicommunity.mcp.security.sample.authorizationserver;

import java.lang.reflect.Field;
import java.sql.Ref;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ClientsController {

	private final InMemoryRegisteredClientRepository registeredClientRepository;

	ClientsController(RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = (InMemoryRegisteredClientRepository) registeredClientRepository;
	}

	@GetMapping("/clients")
	public Collection<RegisteredClient> clients() {
		var clientId = ReflectionUtils.findField(InMemoryRegisteredClientRepository.class, "clientIdRegistrationMap");
		ReflectionUtils.makeAccessible(clientId);
		Map<String, RegisteredClient> clients = (Map<String, RegisteredClient>) ReflectionUtils.getField(clientId,
				registeredClientRepository);
		return clients.values();
	}

}
