package com.authorization.crewservice.config;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Component
public class CustomKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {

    @Autowired
    private HttpServletRequest request;

    public CustomKeycloakAuthenticationProvider() {
        super();
    }

    public CustomKeycloakAuthenticationProvider(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken)authentication;
        List<GrantedAuthority> grantedAuthorities = new ArrayList();
        Iterator var4 = token.getAccount().getRoles().iterator();

        while(var4.hasNext()) {
            String role = (String)var4.next();
            grantedAuthorities.add(new KeycloakRole(role));
        }

        ClientAuthorizationContext clientAuthorizationContext = getAuthorizationContext();


        return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), grantedAuthorities);
    }

    private AuthzClient getAuthzClient() {
        return getAuthorizationContext().getClient();
    }

    private ClientAuthorizationContext getAuthorizationContext() {
        return ClientAuthorizationContext.class.cast(getKeycloakSecurityContext().getAuthorizationContext());
    }

    private KeycloakSecurityContext getKeycloakSecurityContext() {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }
}
