package com.nbd.dockinput.auth.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyStore;
import java.time.Duration;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    /**
     * 授权配置
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(a -> a.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .formLogin().and().logout()
                .and().apply(authorizationServerConfigurer);
        return http.build();
    }


    /**
     * 注册客户端
     *
     * @param jdbcTemplate
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        String clientId = "local_client_id";
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            //创建注册客户端验证码
            registeredClient = createRegisteredAuthorizationCode(clientId);
            registeredClientRepository.save(registeredClient);

        }
        return registeredClientRepository;
    }


    private RegisteredClient createRegisteredAuthorizationCode(final String clientId) {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(2))
                .reuseRefreshTokens(true)
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .build();
        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .build();
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(clientId)
                .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("123456"))
                .clientName("local_client_name")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://os.com:10003/login/oauth2/code/local_client")
                .redirectUri("http://os.com:10003")
                .scope("read")
                .scope("write")
                .tokenSettings(tokenSettings)
                .clientSettings(clientSettings);
        return builder.build();
    }


    /**
     * 令牌发放 记录入库
     *
     * @param jdbcTemplate
     * @param repository
     * @return
     */
    @Bean
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, repository);
    }

    /**
     * 授权确认 记录入库
     *
     * @param jdbcTemplate
     * @param repository
     * @return
     */
    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, repository);
    }

    /**
     * 加载jwk资源
     * 用于生成令牌
     * @return
     * @throws Exception
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        String path = "myjks.jks";
        String alias = "myjks";
        String password = "abcdefg";
        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");
        char[] pin = password.toCharArray();
        jks.load(resource.getInputStream(), pin);
        RSAKey rsaKey = RSAKey.load(jks, alias, pin);
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public ProviderSettings providerSettings() {
        //token发行配置
        return ProviderSettings.builder().issuer("http://os.com:10001").build();
    }
}
