package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
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

import static com.justincranford.springsecurity.webauthn.redis.util.MyGivens.publicKeyCredentialCreationOptions;
import static com.justincranford.springsecurity.webauthn.redis.util.MyGivens.publicKeyCredentialRequestOptions;
import static com.justincranford.springsecurity.webauthn.redis.util.ObjectMapperFactory.objectMapper;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@Slf4j
public class WebauthnObjectMapperMixinsTest {
	// ObjectMapper instances with 0-5 fixes to be used for direct serialization and deserialization
	private static final ObjectMapper OBJECT_MAPPER0 = objectMapper(false, false, false, false, false);
	private static final ObjectMapper OBJECT_MAPPER1 = objectMapper(true,  false, false, false, false);
	private static final ObjectMapper OBJECT_MAPPER2 = objectMapper(true,  true,  false, false, false);
	private static final ObjectMapper OBJECT_MAPPER3 = objectMapper(true,  true,  true,  false, false);
	private static final ObjectMapper OBJECT_MAPPER4 = objectMapper(true,  true,  true,  true,  false);
	private static final ObjectMapper OBJECT_MAPPER5 = objectMapper(true,  true,  true,  true,  true);

	@Order(-1)
	@Nested
	public class ObjectMapperIssue_MissingWebauthnSecurityModule {
		final ObjectMapper objectMapper = new ObjectMapper();
		@Test
		public void demo_security_WebauthnJackson2Module_missingFrom_SecurityJackson2Modules_getModules() {
			objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
			assertThat(objectMapper.getRegisteredModuleIds()).doesNotContain("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");
			objectMapper.registerModule(new WebauthnJackson2Module()); // workaround: manually add
			assertThat(objectMapper.getRegisteredModuleIds()).contains("org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module");
		}
	}

	@Order(0)
	@Nested
	public class ObjectMapperIssue_0Workarounds {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER0, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER0, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
	}

	@Order(1)
	@Nested
	public class ObjectMapperIssue_1Workaround {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER1, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER1, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions` (no Creators, like default constructor, exist): cannot deserialize from Object value (no delegate- or property-based Creator)");
		}
	}

	@Order(2)
	@Nested
	public class ObjectMapperIssue_2Workarounds {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER2, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"extensions\"])");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(InvalidDefinitionException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER2, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Type id handling not implemented for type org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs (by serializer of type org.springframework.security.web.webauthn.jackson.AuthenticationExtensionsClientInputsSerializer) (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions[\"extensions\"])");
		}
	}

	@Order(3)
	@Nested
	public class ObjectMapperIssue_3Workarounds {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(JsonMappingException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER3, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("The class with java.util.ImmutableCollections$ListN and name of java.util.ImmutableCollections$ListN is not in the allowlist. If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. If the serialization is only done by a trusted source, you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"pubKeyCredParams\"])");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(JsonMappingException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER3, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("The class with java.util.ImmutableCollections$List12 and name of java.util.ImmutableCollections$List12 is not in the allowlist. If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. If the serialization is only done by a trusted source, you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions[\"allowCredentials\"])");
		}
	}

	@Order(4)
	@Nested
	public class ObjectMapperIssue_4Workarounds {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			final Exception e = Assertions.assertThrows(MismatchedInputException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER4, publicKeyCredentialCreationOptions()));
			assertThat(e.getMessage()).startsWith("Trailing token (of type FIELD_NAME) found after value (bound as `java.lang.String`): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`");
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			final Exception e = Assertions.assertThrows(MismatchedInputException.class, () -> doSerDesWithObjectMapper(OBJECT_MAPPER4, publicKeyCredentialRequestOptions()));
			assertThat(e.getMessage()).startsWith("Trailing token (of type FIELD_NAME) found after value (bound as `java.lang.String`): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`");
		}
	}

	@Order(5)
	@Nested
	public class ObjectMapperWorking_5Workarounds {
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialCreationOptions() {
			Assertions.assertDoesNotThrow(() -> doSerDesWithObjectMapper(OBJECT_MAPPER5, publicKeyCredentialCreationOptions()));
		}
		@Test
		public void doSerDesWithObjectMapper_publicKeyCredentialRequestOptions() {
			Assertions.assertDoesNotThrow(() -> doSerDesWithObjectMapper(OBJECT_MAPPER5, publicKeyCredentialRequestOptions()));
		}
	}

	private static void doSerDesWithObjectMapper(final ObjectMapper objectMapper, final Object expected) throws JsonProcessingException {
		final String serialized = objectMapper.writeValueAsString(expected);
		log.info("Serialized: {}", serialized);

		final Object actual = objectMapper.readValue(serialized, expected.getClass());
		log.info("Deserialized: {}\n", actual);

		assertThat(actual).isInstanceOf(expected.getClass());
		// Can't to equals() check, because WebAuthn challenge classes do not override equals() methods.
		// Can't do serialize for deep compare, because WebAuthn challenge classes do not implement Serializable interface.
//		Assertions.assertEquals(expected, actual);
	}
}
