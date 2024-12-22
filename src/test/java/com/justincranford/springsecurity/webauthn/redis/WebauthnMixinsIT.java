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

import java.time.Duration;
import java.util.Base64;

import static com.justincranford.springsecurity.webauthn.redis.EmbeddedRedisServerConfig.REDIS_SERVER_ADDRESS;
import static com.justincranford.springsecurity.webauthn.redis.EmbeddedRedisServerConfig.REDIS_SERVER_PORT;
import static com.justincranford.springsecurity.webauthn.redis.MyGivens.publicKeyCredentialCreationOptions;
import static com.justincranford.springsecurity.webauthn.redis.MyGivens.publicKeyCredentialRequestOptions;
import static com.justincranford.springsecurity.webauthn.redis.MyGivens.usernamePasswordAuthenticationToken;
import static com.justincranford.springsecurity.webauthn.redis.ObjectMapperFactory.objectMapper;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ EmbeddedRedisServerConfig.class })
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"unused"})
public class WebauthnMixinsIT {
	// ObjectMapper instances with 0-5 fixes to be injected into Redis Configuration classes
	private static final ObjectMapper OBJECT_MAPPER0 = objectMapper(false, false, false, false, false);
	private static final ObjectMapper OBJECT_MAPPER1 = objectMapper(true,  false, false, false, false);
	private static final ObjectMapper OBJECT_MAPPER2 = objectMapper(true,  true,  false, false, false);
	private static final ObjectMapper OBJECT_MAPPER3 = objectMapper(true,  true,  true,  false, false);
	private static final ObjectMapper OBJECT_MAPPER4 = objectMapper(true,  true,  true,  true,  false);
	private static final ObjectMapper OBJECT_MAPPER5 = objectMapper(true,  true,  true,  true,  true);

	@Configuration public static class MyRedisClientConfig0 extends MyAbstractRedisClientConfig { public MyRedisClientConfig0() { super(OBJECT_MAPPER0); } }
	@Configuration public static class MyRedisClientConfig1 extends MyAbstractRedisClientConfig { public MyRedisClientConfig1() { super(OBJECT_MAPPER1); } }
	@Configuration public static class MyRedisClientConfig2 extends MyAbstractRedisClientConfig { public MyRedisClientConfig2() { super(OBJECT_MAPPER2); } }
	@Configuration public static class MyRedisClientConfig3 extends MyAbstractRedisClientConfig { public MyRedisClientConfig3() { super(OBJECT_MAPPER3); } }
	@Configuration public static class MyRedisClientConfig4 extends MyAbstractRedisClientConfig { public MyRedisClientConfig4() { super(OBJECT_MAPPER4); } }
	@Configuration public static class MyRedisClientConfig5 extends MyAbstractRedisClientConfig { public MyRedisClientConfig5() { super(OBJECT_MAPPER5); } }

	@Order(0)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig0.class })
	public class ObjectMapperIssue_0Workarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final AssertionError e = Assertions.assertThrows(AssertionError.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage().replaceAll("\r", "")).contains("to be an instance of:\n  org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions\nbut was instance of:\n  java.util.LinkedHashMap");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final AssertionError e = Assertions.assertThrows(AssertionError.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage().replaceAll("\r", "")).contains("to be an instance of:\n  org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions\nbut was instance of:\n  java.util.LinkedHashMap");
		}
	}

	@Order(1)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig1.class })
	public class ObjectMapperIssue_1Workaround {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Could not resolve subtype of [simple type, class java.lang.Object]: missing type id property '@class'");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Could not resolve subtype of [simple type, class java.lang.Object]: missing type id property '@class'");
		}
	}

	@Order(2)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig2.class })
	public class ObjectMapperIssue_2Workarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not write JSON: Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"extensions\"])");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not write JSON: Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions[\"extensions\"])");
		}
	}

	@Order(3)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig3.class })
	public class ObjectMapperIssue_3Workarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:The class with java.util.ImmutableCollections$ListN and name of java.util.ImmutableCollections$ListN is not in the allowlist. If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. If the serialization is only done by a trusted source, you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"pubKeyCredParams\"]) ");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:The class with java.util.ImmutableCollections$List12 and name of java.util.ImmutableCollections$List12 is not in the allowlist. If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. If the serialization is only done by a trusted source, you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions[\"allowCredentials\"]) ");
		}
	}

	@Order(4)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig4.class })
	public class ObjectMapperIssue_4Workarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Trailing token (of type FIELD_NAME) found after value (bound as `java.lang.String`): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Could not read JSON:Trailing token (of type FIELD_NAME) found after value (bound as `java.lang.String`): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`");
		}
	}

	@Order(5)
	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig5.class })
	public class RedisSerializerWorking_5Workarounds {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Object expected = publicKeyCredentialCreationOptions();
			final Object actual = redisRepository_save_then_findById(this.sessionRepository, "whatever", expected);
			assertThat(actual).isInstanceOf(expected.getClass());
//			Assertions.assertEquals(actual, expected); // missing equals in WebAuthn challenge classes
		}

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Object expected = publicKeyCredentialRequestOptions();
			final Object actual = redisRepository_save_then_findById(this.sessionRepository, "whatever", expected);
			assertThat(actual).isInstanceOf(expected.getClass());
//			Assertions.assertEquals(actual, expected); // missing equals in WebAuthn challenge classes
		}

		@Test
		public void doSerDesWithRedisSerializer_securityContext_usernamePasswordAuthenticationToken() {
			final UsernamePasswordAuthenticationToken expectedAuthentication = usernamePasswordAuthenticationToken();
			final SecurityContext expectedSecurityContext = SecurityContextHolder.createEmptyContext();
			expectedSecurityContext.setAuthentication(expectedAuthentication);

			final SecurityContext actualSecurityContext = (SecurityContext) redisRepository_save_then_findById(this.sessionRepository, HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, expectedSecurityContext);

			assertThat(actualSecurityContext).isEqualTo(expectedSecurityContext);
			final Authentication actualAuthentication = actualSecurityContext.getAuthentication();
			assertThat(actualSecurityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
			assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
		}
	}

	private static Object redisRepository_save_then_findById(final SessionRepository sessionRepository, final String key, final Object value) {
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

	// Inject different ObjectMapper instances to be used by RedisSerializer<Object>, for setHashValueSerializer and setValueSerializer
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
			redisTemplate.setHashKeySerializer(stringRedisSerializer);
			redisTemplate.setKeySerializer(stringRedisSerializer);
			redisTemplate.setHashValueSerializer(springSessionDefaultRedisSerializer);
			redisTemplate.setValueSerializer(springSessionDefaultRedisSerializer);
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
