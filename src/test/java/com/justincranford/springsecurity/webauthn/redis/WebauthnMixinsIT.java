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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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
	public void demo_security_WebauthnJackson2Module_missingFrom_SecurityJackson2Modules_getModules() {
		final ObjectMapper objectMapper = new ObjectMapper();

		objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
		assertThat(objectMapper.getRegisteredModuleIds()).doesNotContain("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");

		objectMapper.registerModule(new WebauthnJackson2Module()); // manually add it
		assertThat(objectMapper.getRegisteredModuleIds()).contains("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnRegisterChallenge_allFixes() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
		doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions());
	}

	@Test
	public void doSerDesWithObjectMapper_webauthnAuthenticateChallenge_allFixes() throws JsonProcessingException {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
		doSerDesWithObjectMapper(objectMapper, publicKeyCredentialRequestOptions());
	}

	private static void doSerDesWithObjectMapper(final ObjectMapper objectMapper, final Object object) throws JsonProcessingException {
		final String serialized = objectMapper.writeValueAsString(object);
		log.info("Serialized: {}", serialized);
		final Object deserialized = objectMapper.readValue(serialized, object.getClass());
		log.info("Deserialized: {}\n", deserialized);
//		Assertions.assertEquals(object, deserialized);
	}

	@Test
	public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
		final Object expected = publicKeyCredentialCreationOptions();
		final Object actual = redisRepositorySaveFindById(this.sessionRepository, "whatever", expected);
		assertThat(actual).isInstanceOf(expected.getClass());
	}

	@Test
	public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
		final Object expected = publicKeyCredentialRequestOptions();
		final Object actual = redisRepositorySaveFindById(this.sessionRepository, "whatever", expected);
		assertThat(actual).isInstanceOf(expected.getClass());
	}

	@Test
	public void doSerDesWithRedisSerializer_securityContext_usernamePasswordAuthenticationToken() {
		final UsernamePasswordAuthenticationToken expectedAuthentication = usernamePasswordAuthenticationToken();
		final SecurityContext expectedSecurityContext = SecurityContextHolder.createEmptyContext();
		expectedSecurityContext.setAuthentication(expectedAuthentication);

		final SecurityContext actualSecurityContext = (SecurityContext) redisRepositorySaveFindById(this.sessionRepository, HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, expectedSecurityContext);
		final Authentication actualAuthentication = actualSecurityContext.getAuthentication();
		assertThat(actualSecurityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
	}

	@SuppressWarnings({"unchecked"})
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
		public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
			final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
			return GenericJackson2JsonRedisSerializer.builder().objectMapper(objectMapper).build();
		}

		@Bean
		public LettuceConnectionFactory redisConnectionFactory() {
			return new LettuceConnectionFactory("localhost", 6379);
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
