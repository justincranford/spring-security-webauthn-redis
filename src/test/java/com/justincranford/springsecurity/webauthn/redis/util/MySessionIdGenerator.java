package com.justincranford.springsecurity.webauthn.redis.util;

import org.springframework.session.SessionIdGenerator;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Similar goal as UUID Type 7, but with improved security and enhanced usability.
 * Timestamp prefix ensures ordering, and bucketed as 1 hour intervals to prevent guessing precise times.
 * Randomness suffix is increased to 32-bytes, the minimum for NIST to consider it sufficiently unique to be secure.
 * Unsigned short counter extra suffix assisted debugging within each instance of an application (e.g. 0001, ..., FFFE, FFFF, 0000, ...).
 * Base64-URL encoding makes it useful as web session id cookie value, URL magic link query parameter, JWT jti/nonce, etc.
 * Binary data structure is...
 * Bytes (42):  timestamp bucket (8-bytes), random (32-bytes), rollover counter (2-bytes)
 * String encoding size is...
 * String (56): 42 bytes * 4 / 3 => 56 base64-url characters
 */
public class MySessionIdGenerator implements SessionIdGenerator {
	private static final long TIMESTAMP_GRANULARITY = 3600L; // 1 hour granularity
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final AtomicInteger COUNTER = new AtomicInteger(1);
	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	public String generate() {
		return ENCODER.encodeToString(generateBytes());
	}

	public byte[] generateBytes() {
		final long timestampBucket = Instant.now().getEpochSecond() / TIMESTAMP_GRANULARITY;
		final int  rolloverCounter = COUNTER.getAndIncrement();

		final byte[] timestamp = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(timestampBucket).array();
		final byte[] bytes = new byte[32]; // NIST minimum randomness to be considered unique
		SECURE_RANDOM.nextBytes(bytes);
		final byte[] counter = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(rolloverCounter).array();

		final byte[] id = new byte[42];
		System.arraycopy(timestamp, 0, id,  0, 8);
		System.arraycopy(bytes,     0, id,  8, 32);
		System.arraycopy(counter  , 2, id, 40, 2); // last 2-bytes of big endian int
		return id;
	}
}
