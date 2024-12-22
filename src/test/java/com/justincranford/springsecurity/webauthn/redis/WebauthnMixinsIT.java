package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixinsIT.MyRedisClientConfig;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixinsIT.MyRedisServerConfig;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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
		objectMapper(true, true, false, false, false);
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnRegisterChallenge_fixed() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
		doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions());
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnAuthenticateChallenge_fixed() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
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
//		Assertions.assertEquals(object, deserialized);
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
			return objectMapper(true, true, true, true, true);
		}

		@Bean
		public RedisSessionRepository redisSessionRepository(final RedisTemplate<String, Object> sessionRedisTemplate) {
			return new RedisSessionRepository(sessionRedisTemplate);
		}
	}
}
