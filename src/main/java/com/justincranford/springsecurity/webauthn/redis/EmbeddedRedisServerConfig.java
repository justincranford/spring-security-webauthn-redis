package com.justincranford.springsecurity.webauthn.redis;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.embedded.RedisServer;

import java.io.IOException;

@Configuration
public class EmbeddedRedisServerConfig {
	public static final String REDIS_SERVER_ADDRESS = "localhost";
	public static final int REDIS_SERVER_PORT = 6379;

	@Bean(initMethod="start", destroyMethod="stop")
	public RedisServer redisServerEmbedded() throws IOException {
		return new RedisServer(REDIS_SERVER_PORT);
	}
}
