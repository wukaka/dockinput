package com.nbd.dockinput.ncm.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.annotation.Resource;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;

@EnableConfigurationProperties(JwtProperties.class)
@Configuration(proxyBeanMethods = false)
public class JwtDecodeConfig {

    @Resource
    private JwtProperties jwtProperties;

    @Bean
    JwtIssuerValidator jwtIssuerValidator() {
        return new JwtIssuerValidator(this.jwtProperties.getClaims().getIssuer());
    }

    /**
     * jwt token 委托校验器，集中校验的策略{@link OAuth2TokenValidator}
     * <p>
     * // @Primary：自动装配时当出现多个Bean候选者时，被注解为@Primary的Bean将作为首选者，否则将抛出异常
     *
     * @param tokenValidators the token validators * @return the delegating o auth 2 token validator
     */
    @Primary
    @Bean({"delegatingTokenValidator"})
    public DelegatingOAuth2TokenValidator<Jwt> delegatingTokenValidator(Collection<OAuth2TokenValidator<Jwt>> tokenValidators) {
        return new DelegatingOAuth2TokenValidator<>(tokenValidators);
    }


    /**
     * 基于Nimbus的jwt解码器，并增加了一些自定义校验策略
     * // @Qualifier 当有多个相同类型的bean存在时，指定注入
     *
     * @param validator DelegatingOAuth2TokenValidator<Jwt> 委托token校验器
     * @return the jwt decoder
     */
    @Bean
    public JwtDecoder jwtDecoder(@Qualifier("delegatingTokenValidator")
                                         DelegatingOAuth2TokenValidator<Jwt> validator) throws Exception {

        // 指定 X.509 类型的证书工厂
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        // 读取cer公钥证书来配置解码器
        String publicKeyLocation = this.jwtProperties.getCertInfo().getPublicKeyLocation();
        // 获取证书文件输入流
        ClassPathResource resource = new ClassPathResource(publicKeyLocation);
        InputStream inputStream = resource.getInputStream();
        // 得到证书
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        // 解析
        RSAKey rsaKey = RSAKey.parse(certificate);
        // 得到公钥
        RSAPublicKey key = rsaKey.toRSAPublicKey();
        // 构造解码器
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withPublicKey(key).build();
        // 注入自定义JWT校验逻辑
        nimbusJwtDecoder.setJwtValidator(validator);
        return nimbusJwtDecoder;
    }

}
