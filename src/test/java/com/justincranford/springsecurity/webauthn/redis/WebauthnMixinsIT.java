package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ WebauthnMixinsIT.MyRedisServerConfig.class })
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"unused"})
public class WebauthnMixinsIT {
	private static final String REDIS_SERVER_ADDRESS = "localhost";
	private static final int REDIS_SERVER_PORT = 6379;

	@Configuration
	public static class MyRedisServerConfig {
		@Bean(initMethod="start", destroyMethod="stop")
		public RedisServer redisServerEmbedded() throws IOException {
			return new RedisServer(REDIS_SERVER_PORT);
		}
	}

	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ RedisSerializerIssue1.Config.class })
	@Order(1)
	@Nested
	public class RedisSerializerIssue1 {
		@Autowired
		private SessionRepository sessionRepository;

		@Configuration
		public static class Config extends MyAbstractRedisClientConfig {
			public Config() {
				super(objectMapper(true, true, true, false, false));
			}
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepositorySaveFindById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Could not resolve subtype of [simple type, class java.lang.Object]: missing type id property '@class'");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepositorySaveFindById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Could not resolve subtype of [simple type, class java.lang.Object]: missing type id property '@class'");
		}
	}

	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ RedisSerializerIssue2.Config.class })
	@Order(2)
	@Nested
	public class RedisSerializerIssue2 {
		@Autowired
		private SessionRepository sessionRepository;

		@Configuration
		public static class Config extends MyAbstractRedisClientConfig {
			public Config() {
				super(objectMapper(true, true, true, true, false));
			}
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepositorySaveFindById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not write JSON: Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"extensions\"])");
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepositorySaveFindById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not write JSON: Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions[\"extensions\"])");
		}
	}

	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ RedisSerializerWorkarounds.Config.class })
	@Order(3)
	@Nested
	public class RedisSerializerWorkarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Configuration
		public static class Config extends MyAbstractRedisClientConfig {
			public Config() {
				super(objectMapper(true, true, true, true, true));
			}
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Object expected = publicKeyCredentialCreationOptions();
			final Object actual = redisRepositorySaveFindById(this.sessionRepository, "whatever", expected);
			assertThat(actual).isInstanceOf(expected.getClass());
//			Assertions.assertEquals(actual, expected); // missing equals in WebAuthn challenge classes
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Object expected = publicKeyCredentialRequestOptions();
			final Object actual = redisRepositorySaveFindById(this.sessionRepository, "whatever", expected);
			assertThat(actual).isInstanceOf(expected.getClass());
//			Assertions.assertEquals(actual, expected); // missing equals in WebAuthn challenge classes
		}

		@Test
		public void doSerDesWithRedisSerializer_securityContext_usernamePasswordAuthenticationToken() {
			final UsernamePasswordAuthenticationToken expectedAuthentication = usernamePasswordAuthenticationToken();
			final SecurityContext expectedSecurityContext = SecurityContextHolder.createEmptyContext();
			expectedSecurityContext.setAuthentication(expectedAuthentication);

			final SecurityContext actualSecurityContext = (SecurityContext) redisRepositorySaveFindById(this.sessionRepository, HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, expectedSecurityContext);

			assertThat(actualSecurityContext).isEqualTo(expectedSecurityContext);
			final Authentication actualAuthentication = actualSecurityContext.getAuthentication();
			assertThat(actualSecurityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
			assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
		}
	}

	private static Object redisRepositorySaveFindById(final SessionRepository sessionRepository, final String key, final Object value) {
		final Session session = sessionRepository.createSession();
		session.setAttribute(key, value);

		final String sessionId = session.getId();
		log.info("Session ID (Base64-URL): {}", sessionId);
		final byte[] sessionIdBytes = Base64.getUrlDecoder().decode(sessionId);
		log.info("Session ID (HEX):        {}", Hex.encode(sessionIdBytes));

		sessionRepository.save(session); // serialize
		final Session retrievedSession = sessionRepository.findById(sessionId); // deserialize

		assertThat(retrievedSession).isNotNull();
		final Object retrievedValue = retrievedSession.getAttribute(key);
		assertThat(retrievedValue).isInstanceOf(value.getClass());

		return retrievedValue;
	}

	@RequiredArgsConstructor
	public static abstract class MyAbstractRedisClientConfig {
		private final ObjectMapper objectMapper;

		@Bean
		public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
			return GenericJackson2JsonRedisSerializer.builder().objectMapper(this.objectMapper).build();
		}

		@Bean
		public LettuceConnectionFactory redisConnectionFactory() {
			return new LettuceConnectionFactory(REDIS_SERVER_ADDRESS, REDIS_SERVER_PORT);
		}

		@Bean
		public RedisTemplate<String, Object> sessionRedisTemplate(
			final RedisSerializer<Object> springSessionDefaultRedisSerializer,
			final LettuceConnectionFactory redisConnectionFactory
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
		public RedisSessionRepository redisSessionRepository(final RedisTemplate<String, Object> sessionRedisTemplate) {
			return new RedisSessionRepository(sessionRedisTemplate);
		}

		@Bean
		public RedisHttpSessionConfiguration redisHttpSessionConfiguration(
			final RedisSerializer<Object> springSessionDefaultRedisSerializer,
			final RedisConnectionFactory redisConnectionFactory,
			@SpringSessionRedisConnectionFactory final ObjectProvider<RedisConnectionFactory> springSessionRedisConnectionFactory
		) {
			final RedisHttpSessionConfiguration config = new RedisHttpSessionConfiguration();
			config.setSessionIdGenerator(new MySessionIdGenerator());
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
	}
}
