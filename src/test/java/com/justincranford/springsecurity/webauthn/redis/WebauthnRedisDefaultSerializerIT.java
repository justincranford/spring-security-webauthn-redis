package com.justincranford.springsecurity.webauthn.redis;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.serializer.support.SerializationFailedException;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

import static com.justincranford.springsecurity.webauthn.redis.EmbeddedRedisServerConfig.REDIS_SERVER_ADDRESS;
import static com.justincranford.springsecurity.webauthn.redis.EmbeddedRedisServerConfig.REDIS_SERVER_PORT;
import static com.justincranford.springsecurity.webauthn.redis.util.MyGivens.publicKeyCredentialCreationOptions;
import static com.justincranford.springsecurity.webauthn.redis.util.MyGivens.publicKeyCredentialRequestOptions;
import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"unused"})
public class WebauthnRedisDefaultSerializerIT extends AbstractRedisServerIT {
	@Configuration
	public static class MyRedisClientConfig {
		@Bean
		public LettuceConnectionFactory redisConnectionFactory() {
			return new LettuceConnectionFactory(REDIS_SERVER_ADDRESS, REDIS_SERVER_PORT);
		}
	}

	@Nested
	@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ MyRedisClientConfig.class })
	@EnableRedisHttpSession
	public class RedisSerializerFailing_DefaultJdkSerialization {
		@Autowired
		private SessionRepository sessionRepository;

		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).contains("Cannot serialize");
			assertThat(e.getCause()).isInstanceOf(SerializationFailedException.class);
			assertThat(e.getCause().getMessage()).contains("Failed to serialize object using DefaultSerializer");
			assertThat(e.getCause().getCause()).isInstanceOf(IllegalArgumentException.class);
			assertThat(e.getCause().getCause().getMessage()).contains("DefaultSerializer requires a Serializable payload but received an object of type [org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions]");
		}
		@Test
		public void doSerDesWithRedisSerializer_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(SerializationException.class, () -> redisRepository_save_then_findById(this.sessionRepository, "whatever", publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).contains("Cannot serialize");
			assertThat(e.getCause()).isInstanceOf(SerializationFailedException.class);
			assertThat(e.getCause().getMessage()).contains("Failed to serialize object using DefaultSerializer");
			assertThat(e.getCause().getCause()).isInstanceOf(IllegalArgumentException.class);
			assertThat(e.getCause().getCause().getMessage()).contains("DefaultSerializer requires a Serializable payload but received an object of type [org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions]");
		}
	}
}
