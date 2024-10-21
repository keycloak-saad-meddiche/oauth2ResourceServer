package com.saadmeddiche.creditmanagement.security;

import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.authorization.integration.jakarta.ServletPolicyEnforcerFilter;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import static com.saadmeddiche.creditmanagement.enums.ROLES.*;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtConverter jwtConverter;

    @Bean
    @ConfigurationProperties(prefix = "policy-enforcer")
    public PolicyEnforcerConfig policyEnforcerConfig() {
        return new PolicyEnforcerConfig();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http , PolicyEnforcerConfig policyEnforcerConfig) throws Exception {

        http.addFilterAfter(new ServletPolicyEnforcerFilter(httpRequest -> policyEnforcerConfig), BearerTokenAuthenticationFilter.class);

        http.authorizeHttpRequests((authz) -> authz
                .anyRequest().fullyAuthenticated()
        );

        http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter)));
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
