package com.authorization.crewservice.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;

@Configuration
@EnableWebSecurity

//@KeycloakConfiguration

//@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	private HttpServletRequest request;

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
	    KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
	    keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
	    auth.authenticationProvider(keycloakAuthenticationProvider);
		//auth.authenticationProvider(new CustomKeycloakAuthenticationProvider(request));
	}

/*	@Autowired
	private CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider;

	@Override
	protected void configure(
			AuthenticationManagerBuilder auth) throws Exception {

		auth.authenticationProvider(customKeycloakAuthenticationProvider);
	}*/

	/*@Bean
	protected CustomKeycloakAuthenticationProvider customKeycloakAuthenticationProvider() {
		return new CustomKeycloakAuthenticationProvider();
	}*/

	//Required for Single Sign Out
	@Bean
	public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
		return new ServletListenerRegistrationBean<HttpSessionEventPublisher>(new HttpSessionEventPublisher());
	}

	@Bean
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

	////////////
	@Bean
	public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
			KeycloakAuthenticationProcessingFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}

/*
	@Bean
	public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
			KeycloakPreAuthActionsFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}
*/

/*	@Bean
	public FilterRegistrationBean keycloakAuthenticatedActionsFilterBean(
			KeycloakAuthenticatedActionsFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}*/

/*	@Bean
	public FilterRegistrationBean keycloakSecurityContextRequestFilterBean(
			KeycloakSecurityContextRequestFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}*/
	//////////

	//////////////////////
	/*@Bean
	public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
			KeycloakAuthenticationProcessingFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}

	@Bean
	public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
			KeycloakPreAuthActionsFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}

	@Bean
	public FilterRegistrationBean keycloakAuthenticatedActionsFilterBean(
			KeycloakAuthenticatedActionsFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}

	@Bean
	public FilterRegistrationBean keycloakSecurityContextRequestFilterBean(
			KeycloakSecurityContextRequestFilter filter) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
		registrationBean.setEnabled(false);
		return registrationBean;
	}

	@Bean
	@Override
	@ConditionalOnMissingBean(HttpSessionManager.class)
	protected HttpSessionManager httpSessionManager() {
		return new HttpSessionManager();
	}*/
	///////////////

/*	@Bean
	public KeycloakConfigResolver KeycloakConfigResolver() {
	    return new KeycloakSpringBootConfigResolver();
	}*/

	@Bean
	public KeycloakConfigResolver keycloakConfigResolver() {
		return new KeycloakConfigResolver() {

			private KeycloakDeployment keycloakDeployment;

			@Override
			public KeycloakDeployment resolve(HttpFacade.Request facade) {
				if (keycloakDeployment != null) {
					return keycloakDeployment;
				}

				String path = "/keycloak.json";
				InputStream configInputStream = getClass().getResourceAsStream(path);

				if (configInputStream == null) {
					throw new RuntimeException("Could not load Keycloak deployment info: " + path);
				} else {
					keycloakDeployment = KeycloakDeploymentBuilder.build(configInputStream);
				}

				return keycloakDeployment;
			}
		};
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http.authorizeRequests()
				.anyRequest()
				.permitAll();
		http.csrf().disable();
	}
}
