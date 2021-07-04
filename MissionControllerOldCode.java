package com.authorization.crewservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/api/missions/old")
public class MissionControllerOldCode {

    @Autowired
    private HttpServletRequest request;

    @PostMapping("/create-mission-old")
    public String editPersonnelDetails() {

        //Retrieve
        ClientAuthorizationContext context = getAuthorizationContext();


        AuthzClient authzClient = AuthzClient.create();
       /* AuthorizationResource authResource = authzClient.authorization(getKeycloakSecurityContext().getTokenString());
        AuthorizationRequest authRequest = new AuthorizationRequest();
        authRequest.addPermission(null, "create-mission", "scheduler-create-mission");
        authResource.authorize(authRequest).getToken();
*/
        AuthorizationRequest request = new AuthorizationRequest();
        /*AuthorizationResponse response = authzClient.authorization("user-scheduler", "password")
                .authorize(request);*/
        AuthorizationResponse response = authzClient.authorization(getKeycloakSecurityContext().getTokenString())
                .authorize(request);
        String token = response.getToken();
        System.out.println(token);

        // split out the "parts" (header, payload and signature)
        Base64.Decoder decoder = Base64.getDecoder();
        String[] parts = token.split("\\.");

        String headerJson = new String(decoder.decode(parts[0]));
        String payloadJson = new String(decoder.decode(parts[1]));
        //String signatureJson = new String(decoder.decode(parts[2]));



/*        Gson g = new Gson();
        AccessToken payload = g.fromJson(payloadJson, AccessToken.class);*/

        AccessToken payload = new AccessToken();
        try {
            payload = new ObjectMapper().readValue(payloadJson, AccessToken.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Retrieve Roles
        Set<String> roles = new HashSet<>();
        roles = payload.getRealmAccess().getRoles();

        //Retrieve Scopes
        Set<String> scopes = new HashSet<>();
        payload.getAuthorization().getPermissions().forEach(p -> {
            scopes.addAll(p.getScopes());
        });




/*        authzClient.protection().resource()
                .find(null,null,null,null, "The-Type-I-Want", null, false, 0, Integer.MAX_VALUE);*/






        return "Mission created";
     }

    private KeycloakSecurityContext getKeycloakSecurityContext() {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }

    private AuthzClient getAuthzClient() {
        ClientAuthorizationContext clientAuthorizationContext = getAuthorizationContext();
        return getAuthorizationContext().getClient();
    }

    private ClientAuthorizationContext getAuthorizationContext() {
        return ClientAuthorizationContext.class.cast(getKeycloakSecurityContext().getAuthorizationContext());
    }


}

