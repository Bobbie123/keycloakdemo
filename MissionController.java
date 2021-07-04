package com.authorization.crewservice.controller;

import com.authorization.crewservice.model.AuthToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.tomcat.util.http.parser.Authorization;
import org.apache.tomcat.util.json.JSONParser;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authorization.authorization.AuthorizationTokenService;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.authorization.client.resource.AuthorizationResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import twitter4j.JSONException;
import twitter4j.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/missions")
public class MissionController {

    @Autowired
    private HttpServletRequest request;

    @PostMapping("/create-mission")
    public String editPersonnelDetails() {

       AccessToken payload = getPayload();

       //Retrieve Roles and Scopes
       Set<String> roles = getAllRoles(payload);
       Set<String> scopes = getAllScopes(payload);

       if(roles.contains("planner") && scopes.contains("planner-create-mission")){
           //Execute for Plamner
           return "Planner Mission created";
       }else if(roles.contains("scheduler") && scopes.contains("scheduler-create-mission")){
           //Execute for Scheduler
           return "Scheduler Mission created";
       }
       return null;

    }

    private AccessToken getPayload(){
        //Get Auth token and get Payload out of it
        //Split out the "parts" (header, payload and signature)
        Base64.Decoder decoder = Base64.getDecoder();
        String[] parts = getAuthorizationToken().split("\\.");

        String headerJson = new String(decoder.decode(parts[0]));
        String payloadJson = new String(decoder.decode(parts[1]));
        //String signatureJson = new String(decoder.decode(parts[2]));

        AccessToken payload = new AccessToken();
        try {
            payload = new ObjectMapper().readValue(payloadJson, AccessToken.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return payload;
    }

    private String getAuthorizationToken(){
        AuthzClient authzClient = AuthzClient.create();
        AuthorizationRequest request = new AuthorizationRequest();
        AuthorizationResponse response = authzClient.authorization(getKeycloakSecurityContext().getTokenString())
                .authorize(request);
        return response.getToken();
    }

    private Set<String> getAllRoles(AccessToken payload){
        Set<String> roles = new HashSet<>();
        roles = payload.getRealmAccess().getRoles();
        return roles;
    }

    private Set<String> getAllScopes(AccessToken payload){
        Set<String> scopes = new HashSet<>();
        payload.getAuthorization().getPermissions().forEach(p -> {
            scopes.addAll(p.getScopes());
        });
        return scopes;
    }

    private KeycloakSecurityContext getKeycloakSecurityContext() {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }

/*    private AuthzClient getAuthzClient() {
        ClientAuthorizationContext clientAuthorizationContext = getAuthorizationContext();
        return getAuthorizationContext().getClient();
    }

    private ClientAuthorizationContext getAuthorizationContext() {
        return ClientAuthorizationContext.class.cast(getKeycloakSecurityContext().getAuthorizationContext());
    }*/
}

