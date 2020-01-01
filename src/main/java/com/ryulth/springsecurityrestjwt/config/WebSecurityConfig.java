package com.ryulth.springsecurityrestjwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Order(1)
    @Configuration
    public static class JWTRestSecurityConfig extends WebSecurityConfigurerAdapter {
        private static final RequestMatcher PROTECTED_URLS = new OrRequestMatcher(
                new AntPathRequestMatcher("/api/**")
        );

        JWTTokenAuthenticationProvider provider;

        JWTRestSecurityConfig(JWTTokenAuthenticationProvider provider) {
            super();
            this.provider = requireNonNull(provider);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(provider);
        }

        @Override
        public void configure(WebSecurity web) {
            web.ignoring().mvcMatchers(HttpMethod.OPTIONS, "/**");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .sessionManagement()
                    .sessionCreationPolicy(STATELESS)
                    .and()
                    .exceptionHandling()
                    // this entry point handles when you request a protected page and you are not yet
                    // authenticated
                    .defaultAuthenticationEntryPointFor(forbiddenEntryPoint(), PROTECTED_URLS)
                    .and()
                    .authenticationProvider(provider)
                    .addFilterBefore(restAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                    .authorizeRequests()
                    .requestMatchers(PROTECTED_URLS)
                    .authenticated()
                    .and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable()
                    .logout().disable();

        }

        @Bean
        TokenAuthenticationFilter restAuthenticationFilter() throws Exception {
            final TokenAuthenticationFilter filter = new TokenAuthenticationFilter(PROTECTED_URLS);
            filter.setAuthenticationManager(authenticationManager());
            filter.setAuthenticationSuccessHandler(successHandler());
            return filter;
        }

        @Bean
        SimpleUrlAuthenticationSuccessHandler successHandler() {
            final SimpleUrlAuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler();
            successHandler.setRedirectStrategy(new NoRedirectStrategy());
            return successHandler;
        }

        /**
         * Disable Spring boot automatic filter registration.
         */
        @Bean
        FilterRegistrationBean disableAutoRegistration(final TokenAuthenticationFilter filter) {
            final FilterRegistrationBean registration = new FilterRegistrationBean(filter);
            registration.setEnabled(false);
            return registration;
        }

        @Bean
        AuthenticationEntryPoint forbiddenEntryPoint() {
            return new HttpStatusEntryPoint(FORBIDDEN);
        }
    }

    @Order(2)
    @Configuration
    public static class SwaggerSecurityConfig extends WebSecurityConfigurerAdapter {
        private static final RequestMatcher SWAGGER_URLS = new OrRequestMatcher(
                new AntPathRequestMatcher("/v2/api-docs")
        );
        private static final String SWAGGER = "SWAGGER";

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                    .withUser("admin").password(passwordEncoder().encode("1234")).roles(SWAGGER);
        }
        @Override
        public void configure(WebSecurity web) {
            web.ignoring().mvcMatchers(HttpMethod.OPTIONS, "/**");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .requestMatchers(SWAGGER_URLS).hasRole(SWAGGER)
                    .and()
                    .csrf().disable()
                    .httpBasic();
        }

        @Bean
        PasswordEncoder passwordEncoder() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
    }

}
