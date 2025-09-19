package org.springaicommunity.mcp.security.resourceserver.jwt;

import java.util.Collection;
import org.springaicommunity.mcp.security.resourceserver.metadata.ResourceIdentifier;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;

/**
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
