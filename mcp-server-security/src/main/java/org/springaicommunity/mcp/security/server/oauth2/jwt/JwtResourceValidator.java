/*
 * Copyright 2025-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.server.oauth2.jwt;

import java.util.Collection;

import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;

/**
 * Validate the {@code "aud"} claim of a JWT, ensuring it matches the resource identifier
 * of this MCP server.
 *
 * @author Daniel Garnier-Moiroux
 */
public class JwtResourceValidator implements OAuth2TokenValidator<Jwt> {

	private final JwtClaimValidator<Collection<String>> validator;

	public JwtResourceValidator(ResourceIdentifier resourceIdentifier) {
		this.validator = new JwtClaimValidator<>(JwtClaimNames.AUD,
				(claimValue) -> (claimValue != null) && claimValue.contains(resourceIdentifier.getResource()));
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		return this.validator.validate(token);
	}

}
