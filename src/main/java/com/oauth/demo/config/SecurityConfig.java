package com.oauth.demo.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig
{

    @Bean
    @Order(1)
    public SecurityFilterChain webFilterChainForOAuth(HttpSecurity httpSecurity) throws Exception
    {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(x->x.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
        ));

        return httpSecurity.build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService()
    {
        User user = (User) User.withUsername("mehmet")
                .password("pass")
                .authorities("read")
                .roles("VIEWER")
                .build();

        User adminUser = (User) User.withUsername("admin")
            .password("pass")
            .authorities("read")
            .roles("VIEWER","ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user,adminUser);
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository()
    {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("app-client-id")
                .clientSecret("app-client-secret")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://127.0.0.1:8083/login/oauth2/code/app-client-id")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // public client
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantTypes(
                        grantType -> {
                            grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                            grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
                            grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                        }
                ).clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(){
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keys = keyPairGenerator.generateKeyPair();
        PublicKey aPublic = keys.getPublic();
        PrivateKey aPrivate = keys.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) aPublic)
                .privateKey(aPrivate)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource)
    {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtEncodingContextOAuth2TokenCustomizer()
    {

        return context -> {
            if(context.getTokenType().getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue()))
            {
                Authentication principle = context.getPrincipal();
                Set<String> authorities = principle.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

                context.getClaims().claim("authorities",authorities);
            }

        };
    }


    //http://127.0.0.1:8083/login/oauth2/code/app-client-id?code=
    // agDIVgw4Kx5xN-bekIwE_W5w7Puxwqxz0rSl2cCgBBWrIPObaVW0pwlnPhuhtlUe3aY7FyvCocGz_iIyG_BdHT_Anrym1MkrBuqsw_3xvosVPHlHDnnSHY4LpcHbKDDR




    //http://127.0.0.1:8083/login/oauth2/code/app-client-id?code=
    // 7q9L8myw6ri2rcwWZ6eXvSkoH7BaAWeQHWP2At8mTF5iNRLrrzCz4IIfoUSMYMzXjWfb685MCJy5-TXzvb4f-xW_bstRWoPHg_8U5_rMsPx99MbSALZHGJIOKzYERlu2


    //http://127.0.0.1:8083/login/oauth2/code/app-client-id?code=
    // afwEB19Y5o8cGu4O6E5m2DfQ1AyA6TvsCyEk5fByixkovtATb9ecqn0jiIYon4RCPR9kC7uKONY8Do-PH1AFIWuyVlSTmZ5n-A87zWOwWslZdA5MEMh21E3Qc4_vLC4u


    // http://127.0.0.1:8083/login/oauth2/code/app-client-id?code=
    // 2juB753o80C_cJWjKwd92nEp4Q-sPw8-KwDejLdtADgvsII38StqfY_1cQSwpbaaQ3a7Aco-z4W9VSOESYM4oes-gsqMGsUtn8H3kSiANbZKIVo4gOVLlIkIt62JSMYR
}
