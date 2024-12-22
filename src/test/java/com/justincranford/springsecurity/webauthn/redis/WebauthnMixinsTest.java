package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static com.justincranford.springsecurity.webauthn.redis.Givens.objectMapper;
import static com.justincranford.springsecurity.webauthn.redis.Givens.publicKeyCredentialCreationOptions;
import static com.justincranford.springsecurity.webauthn.redis.Givens.publicKeyCredentialRequestOptions;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@Slf4j
public class WebauthnMixinsTest {
	@Order(1)
	@Nested
	public class ObjectMapperIssue1 {
		final ObjectMapper objectMapper = new ObjectMapper();
		@Test
		public void demo_security_WebauthnJackson2Module_missingFrom_SecurityJackson2Modules_getModules() {
			objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
			assertThat(objectMapper.getRegisteredModuleIds()).doesNotContain("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");
			objectMapper.registerModule(new WebauthnJackson2Module()); // manually add it
			assertThat(objectMapper.getRegisteredModuleIds()).contains("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");
		}
	}

	@Order(2)
	@Nested
	public class ObjectMapperIssue2 {
		final ObjectMapper objectMapper = objectMapper(true, true, true, false, false);
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions_allFixes() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions_allFixes() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
	}

	@Order(3)
	@Nested
	public class ObjectMapperIssue3 {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, false);
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions_allFixes() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions_allFixes() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs");
		}
	}

	@Order(4)
	@Nested
	public class ObjectMapperWorkarounds {
		final ObjectMapper objectMapper = objectMapper(true, true, true, true, true);
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions_allFixes() {
			Assertions.assertDoesNotThrow(() -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialCreationOptions()));
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions_allFixes() {
			Assertions.assertDoesNotThrow(() -> doSerDesWithObjectMapper(objectMapper, publicKeyCredentialRequestOptions()));
		}
	}

	private static void doSerDesWithObjectMapper(final ObjectMapper objectMapper, final Object expected) throws JsonProcessingException {
		final String serialized = objectMapper.writeValueAsString(expected);
		log.info("Serialized: {}", serialized);
		final Object actual = objectMapper.readValue(serialized, expected.getClass());
		log.info("Deserialized: {}\n", actual);
		assertThat(actual).isInstanceOf(expected.getClass());
//		Assertions.assertEquals(expected, actual); // missing equals in WebAuthn challenge classes
	}
}
