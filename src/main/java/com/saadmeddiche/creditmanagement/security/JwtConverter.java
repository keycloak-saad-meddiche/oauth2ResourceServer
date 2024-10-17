package com.saadmeddiche.creditmanagement.security;

import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter converter;

    private final JwtConverterProperties properties;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {

        Collection<GrantedAuthority> authorities = Stream
                .concat(converter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Set<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        @SuppressWarnings("unchecked")
        Map<String, Object> resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId());

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) resource.get("roles");

        if(!CollectionUtils.isEmpty(roles)) {
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority(buildRole(role)))
                    .collect(Collectors.toSet());
        }

        return Collections.emptySet();
    }

    private String buildRole(String role) {
        return String.format("ROLE_%s", role.toUpperCase());
    }
}
