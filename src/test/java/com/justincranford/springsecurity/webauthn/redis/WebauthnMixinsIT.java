package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticationExtensionsClientInputMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticationExtensionsClientInputsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticatorSelectionCriteriaMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.CredProtectAuthenticationExtensionsClientInputMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.CredProtectMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialCreationOptionsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialDescriptorMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialParametersMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialRequestOptionsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialRpEntityMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialUserEntityMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixinsIT.MyRedisClientConfig;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixinsIT.MyRedisServerConfig;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.SpringSessionRedisConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration;
import org.springframework.test.context.ActiveProfiles;
import redis.embedded.RedisServer;

import java.io.IOException;
import java.time.Duration;
import java.util.Base64;
import java.util.Set;

import static com.justincranford.springsecurity.webauthn.redis.Givens.objectMapper;
import static com.justincranford.springsecurity.webauthn.redis.Givens.publicKeyCredentialCreationOptions;
import static com.justincranford.springsecurity.webauthn.redis.Givens.publicKeyCredentialRequestOptions;
import static com.justincranford.springsecurity.webauthn.redis.Givens.usernamePasswordAuthenticationToken;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisServerConfig.class, MyRedisClientConfig.class })
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"unused", "rawtypes"})
public class WebauthnMixinsIT {
	@Autowired
	private SessionRepository sessionRepository;

	@Test
	public void demoMissing_WebauthnJackson2Module() throws JsonProcessingException {
		final ObjectMapper objectMapper = new ObjectMapper();

		assertThat(objectMapper.getRegisteredModuleIds()).isEmpty();

		// verify modules added via SecurityJackson2Modules.getModules()
		objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
		assertThat(objectMapper.getRegisteredModuleIds()).containsExactly(
			"org.springframework.security.jackson2.CoreJackson2Module",
			"org.springframework.security.web.jackson2.WebJackson2Module",
			"org.springframework.security.web.server.jackson2.WebServerJackson2Module",
			"org.springframework.security.web.jackson2.WebServletJackson2Module",
			"jackson-datatype-jsr310"
		);
		assertThat(objectMapper.getRegisteredModuleIds()).doesNotContain("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");

		// verify modules after manually adding WebauthnJackson2Module
		objectMapper.registerModule(new WebauthnJackson2Module());
		assertThat(objectMapper.getRegisteredModuleIds()).containsExactly(
			"org.springframework.security.jackson2.CoreJackson2Module",
			"org.springframework.security.web.jackson2.WebJackson2Module",
			"org.springframework.security.web.server.jackson2.WebServerJackson2Module",
			"org.springframework.security.web.jackson2.WebServletJackson2Module",
			"jackson-datatype-jsr310",
			"org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module"
		);
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnRegisterChallenge() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper();
		objectMapper.registerModule(new WebauthnJackson2Module());
		addMyWebauthnMixins(objectMapper);
		doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions());
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnAuthenticateChallenge() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper();
		objectMapper.registerModule(new WebauthnJackson2Module());
		addMyWebauthnMixins(objectMapper);
		doSerDesWithObjectMapper(objectMapper, publicKeyCredentialRequestOptions());
	}

	@Test
	public void doServerWithRedisSerializer_usernamePasswordAuthenticationToken() {
		doSerDesWithRedisRepository(this.sessionRepository, usernamePasswordAuthenticationToken());
	}

	private static void doSerDesWithObjectMapper(final ObjectMapper objectMapper, final Object object) throws JsonProcessingException {
		final String serialized = objectMapper.writeValueAsString(object);
		log.info("Serialized: {}", serialized);
		final Object deserialized = objectMapper.readValue(serialized, object.getClass());
		log.info("Deserialized: {}\n", deserialized);
		Assertions.assertEquals(object, deserialized);
	}

	public static void addMyWebauthnMixins(final ObjectMapper objectMapper) {
//        objectMapper.addMixIn(Bytes.class, WebauthnBytesMixIn.class);

		objectMapper.addMixIn(PublicKeyCredentialCreationOptions.class, PublicKeyCredentialCreationOptionsMixIn.class);
		objectMapper.addMixIn(ImmutablePublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
		objectMapper.addMixIn(PublicKeyCredentialRpEntity.class, PublicKeyCredentialRpEntityMixIn.class);
		objectMapper.addMixIn(PublicKeyCredentialParameters.class, PublicKeyCredentialParametersMixIn.class);
//        objectMapper.addMixIn(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixIn.class);
//        objectMapper.addMixIn(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixIn.class);
		objectMapper.addMixIn(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixIn.class);
//        objectMapper.addMixIn(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixIn.class);
//        objectMapper.addMixIn(AuthenticatorAttachment.class, AuthenticatorAttachmentMixIn.class);
//        objectMapper.addMixIn(ResidentKeyRequirement.class, ResidentKeyRequirementMixIn.class);
//        objectMapper.addMixIn(UserVerificationRequirement.class, UserVerificationRequirementMixIn.class);
//
		objectMapper.addMixIn(PublicKeyCredentialRequestOptions.class, PublicKeyCredentialRequestOptionsMixIn.class);
		objectMapper.addMixIn(ImmutableAuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
		objectMapper.addMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
		objectMapper.addMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixIn.class);
		objectMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixIn.class);
//        objectMapper.addMixIn(AuthenticatorTransport.class, AuthenticatorTransportMixIn.class);
		objectMapper.addMixIn(CredProtectAuthenticationExtensionsClientInput.class, CredProtectAuthenticationExtensionsClientInputMixIn.class);
		objectMapper.addMixIn(CredProtect.class, CredProtectMixIn.class);
	}

	@SuppressWarnings({"unchecked"})
	private static void doSerDesWithRedisRepository(final SessionRepository sessionRepository, final Authentication expectedAuthentication) {
		// Create SecurityContext
		final SecurityContext expectedSecurityContext = SecurityContextHolder.createEmptyContext();
		expectedSecurityContext.setAuthentication(expectedAuthentication);

		// Persist SecurityContext; serialized in Redis
		final Session session = sessionRepository.createSession();
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, expectedSecurityContext);
		sessionRepository.save(session);
		final String sessionId = session.getId();
		log.info("Session ID (Base64-URL): {}", sessionId);
		final byte[] sessionIdBytes = Base64.getUrlDecoder().decode(sessionId);
		log.info("Session ID (HEX):        {}", Hex.encode(sessionIdBytes));

		// Read SecurityContext, deserialized from Redis
		final Session retrievedSession = sessionRepository.findById(sessionId);
		assertThat(retrievedSession).isNotNull();

		// Compare read SecurityContext to created SecurityContext
		final Object deserializedSecurityContext = retrievedSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		assertThat(deserializedSecurityContext).isInstanceOf(SecurityContext.class);
		final SecurityContext actualSecurityContext = (SecurityContext) deserializedSecurityContext;
		assertThat(actualSecurityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);

		// Compare read Authentication to created Authentication
		final Authentication actualAuthentication = actualSecurityContext.getAuthentication();
		assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
		assertThat(actualAuthentication.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_ADM");
	}

	@Configuration
	public static class MyRedisServerConfig {
		@Bean(initMethod="start",destroyMethod="stop")
		public RedisServer redisServerEmbedded(final Environment environment) throws IOException {
			return new RedisServer(6379);
		}
	}

	@Configuration
	public static class MyRedisClientConfig {
		@Bean
		public LettuceConnectionFactory redisConnectionFactory() {
			return new LettuceConnectionFactory("localhost", 6379);
		}

		@Bean
		public RedisTemplate<String, Object> sessionRedisTemplate(
			final LettuceConnectionFactory redisConnectionFactory,
			final RedisSerializer<Object> springSessionDefaultRedisSerializer
		) {
			final StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
			final RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
			redisTemplate.setConnectionFactory(redisConnectionFactory);
			redisTemplate.setKeySerializer(stringRedisSerializer);
			redisTemplate.setHashKeySerializer(stringRedisSerializer);
			redisTemplate.setValueSerializer(springSessionDefaultRedisSerializer);
			redisTemplate.setHashValueSerializer(springSessionDefaultRedisSerializer);
			redisTemplate.setDefaultSerializer(springSessionDefaultRedisSerializer);
			log.info("redisTemplate: {}", redisTemplate);
			return redisTemplate;
		}

		@Bean
		public RedisHttpSessionConfiguration redisHttpSessionConfiguration(
			@SpringSessionRedisConnectionFactory ObjectProvider<RedisConnectionFactory> springSessionRedisConnectionFactory,
			RedisSerializer<Object> springSessionDefaultRedisSerializer,
			final RedisConnectionFactory redisConnectionFactory
		) {
			final RedisHttpSessionConfiguration config = new RedisHttpSessionConfiguration();
			config.setSessionIdGenerator(new CustomSessionIdGenerator());
			config.setMaxInactiveInterval(Duration.ofSeconds(7));
			config.setRedisNamespace("test");
			config.setDefaultRedisSerializer(springSessionDefaultRedisSerializer);
			final ObjectProvider<RedisConnectionFactory> objectProvider = new ObjectProvider<>() {
				@Override
				public RedisConnectionFactory getObject() throws BeansException {
					return redisConnectionFactory;
				}
			};
			config.setRedisConnectionFactory(objectProvider, objectProvider);
			return config;
		}

		@Bean(name="springSessionDefaultRedisSerializer")
		public RedisSerializer<Object> springSessionDefaultRedisSerializer(@Qualifier("springSessionDefaultObjectMapper") final ObjectMapper springSessionDefaultObjectMapper) {
			return GenericJackson2JsonRedisSerializer.builder().objectMapper(springSessionDefaultObjectMapper).build();
		}

		@Qualifier("springSessionDefaultObjectMapper")
		@Bean
		public ObjectMapper springSessionDefaultObjectMapper() {
			final ObjectMapper objectMapper = objectMapper();

			// Registers CoreJackson2Module (e.g. SimpleGrantedAuthorityMixin) and many others
			objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));

			// Relax deserialization to handle this cryptic Collections$UnmodifiableRandomAccessList nested serialization:
			//    "authorities" : [ "java.util.Collections$UnmodifiableRandomAccessList", [ {
			//      "@class" : "org.springframework.security.core.authority.SimpleGrantedAuthority",
			//      "authority" : "ROLE_ADM"
			//    } ] ],
			objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);

			objectMapper.activateDefaultTyping(
				LaissezFaireSubTypeValidator.instance,
				ObjectMapper.DefaultTyping.NON_FINAL,
				JsonTypeInfo.As.PROPERTY
			);
			return objectMapper;
		}

		@Bean
		public RedisSessionRepository redisSessionRepository(final RedisTemplate<String, Object> sessionRedisTemplate) {
			return new RedisSessionRepository(sessionRedisTemplate);
		}
	}
}
