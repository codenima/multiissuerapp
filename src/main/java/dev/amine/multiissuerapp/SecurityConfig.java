package dev.amine.multiissuerapp;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${idp.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String keycloakIssuerUri;
    @Value("${idp.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String keycloakJwkSetUri;
    @Value("${idp.security.oauth2.resourceserver.jwt.public-key}")
    private String keycloakPublicKey;

    @Value("${apim.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String apimIssuerUri;
    @Value("${apim.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String apimJwkSetUri;
    @Value("${apim.security.oauth2.resourceserver.jwt.public-key}")
    private String apimPublicKey;

    @Bean
    @Order(1)
    public SecurityFilterChain keycloakSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/back/**")
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                    jwt.decoder(keycloakJwtDecoder())
                )
            );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apimSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                    jwt.decoder(apimJwtDecoder())
                )
            );

        return http.build();
    }

    @Bean
    public JwtDecoder keycloakJwtDecoder() {
        return (keycloakPublicKey != null) ? 
        NimbusJwtDecoder.withPublicKey(getPublicKeyFromString(keycloakPublicKey)).build():
        NimbusJwtDecoder.withJwkSetUri(keycloakJwkSetUri).build();
    }

    @Bean
    public JwtDecoder apimJwtDecoder() {
        return (apimPublicKey != null) ? 
        NimbusJwtDecoder.withPublicKey(getPublicKeyFromString(apimPublicKey)).build():
        NimbusJwtDecoder.withJwkSetUri(apimJwkSetUri).build();    
    }

    private RSAPublicKey getPublicKeyFromString(String key) {
        try {
            String publicKeyPEM = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse public key", e);
        }
    }
    
}