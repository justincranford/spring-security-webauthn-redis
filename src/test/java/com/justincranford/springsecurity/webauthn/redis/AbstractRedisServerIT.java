package com.justincranford.springsecurity.webauthn.redis;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.TestClassOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment=WebEnvironment.NONE, classes={ EmbeddedRedisServerConfig.class })
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"unused"})
public abstract class AbstractRedisServerIT {
    protected static Object redisRepository_save_then_findById(final SessionRepository sessionRepository, final String key, final Object value) {
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
}
