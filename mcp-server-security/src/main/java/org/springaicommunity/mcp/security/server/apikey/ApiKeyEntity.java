package org.springaicommunity.mcp.security.server.apikey;

import java.util.Collections;
import java.util.List;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;

public interface ApiKeyEntity extends ApiKey, CredentialsContainer {

	default List<GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	<T extends ApiKeyEntity> T copy();

}
