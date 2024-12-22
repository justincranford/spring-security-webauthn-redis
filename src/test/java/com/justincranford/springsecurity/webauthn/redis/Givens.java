package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticationExtensionsClientInputMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticationExtensionsClientInputsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.AuthenticatorSelectionCriteriaMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.CredProtectAuthenticationExtensionsClientInputMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.CredProtectMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialCreationOptionsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialDescriptorMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialParametersMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialRequestOptionsMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialRpEntityMixIn;
import com.justincranford.springsecurity.webauthn.redis.WebauthnMixins.PublicKeyCredentialUserEntityMixIn;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
public final class Givens {
	private static final ClassLoader CLASS_LOADER = Givens.class.getClassLoader();

	public static ObjectMapper objectMapper(
		final boolean addDefaultSecurityModules,
		final boolean relaxTrainingTokensConstraint,
		final boolean overrideDefaultTypingFromDefaultModules,
		final boolean addMissingSecurityModuleWebauthn,
		final boolean addMyWebauthnMixins
	) {
		final ObjectMapper objectMapper = new ObjectMapper()
			.registerModule(new JavaTimeModule())
			.registerModule(new Jdk8Module())
			.setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
			.enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
			.configure(SerializationFeature.INDENT_OUTPUT, true)
			.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
			.configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
			.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
			.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
			.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true)
			.configure(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY, true)
			.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, true)
			.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false)
			.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
			.configure(DeserializationFeature.FAIL_ON_UNEXPECTED_VIEW_PROPERTIES, true)
			.configure(DeserializationFeature.ACCEPT_FLOAT_AS_INT, false)
			;

		if (addDefaultSecurityModules) {
			objectMapper.registerModules(SecurityJackson2Modules.getModules(CLASS_LOADER));
		}

		if (relaxTrainingTokensConstraint) {
			// Relax deserialization to handle this cryptic Collections$UnmodifiableRandomAccessList nested serialization:
			//    "authorities" : [ "java.util.Collections$UnmodifiableRandomAccessList", [ {
			//      "@class" : "org.springframework.security.core.authority.SimpleGrantedAuthority",
			//      "authority" : "ROLE_ADM"
			//    } ] ],
			objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);
		}

		if (overrideDefaultTypingFromDefaultModules) {
			objectMapper.activateDefaultTyping(
				LaissezFaireSubTypeValidator.instance,
				ObjectMapper.DefaultTyping.NON_FINAL,
				JsonTypeInfo.As.PROPERTY
			);
		}

		if (addMissingSecurityModuleWebauthn) {
			objectMapper.registerModule(new WebauthnJackson2Module());
		}

		if (addMyWebauthnMixins) {
//          objectMapper.addMixIn(Bytes.class, WebauthnBytesMixIn.class);

			objectMapper.addMixIn(PublicKeyCredentialCreationOptions.class, PublicKeyCredentialCreationOptionsMixIn.class);
			objectMapper.addMixIn(ImmutablePublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialRpEntity.class, PublicKeyCredentialRpEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialParameters.class, PublicKeyCredentialParametersMixIn.class);
//          objectMapper.addMixIn(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixIn.class);
//          objectMapper.addMixIn(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixIn.class);
			objectMapper.addMixIn(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixIn.class);
//          objectMapper.addMixIn(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixIn.class);
//          objectMapper.addMixIn(AuthenticatorAttachment.class, AuthenticatorAttachmentMixIn.class);
//          objectMapper.addMixIn(ResidentKeyRequirement.class, ResidentKeyRequirementMixIn.class);
//          objectMapper.addMixIn(UserVerificationRequirement.class, UserVerificationRequirementMixIn.class);

			objectMapper.addMixIn(PublicKeyCredentialRequestOptions.class, PublicKeyCredentialRequestOptionsMixIn.class);
			objectMapper.addMixIn(ImmutableAuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
			objectMapper.addMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
			objectMapper.addMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixIn.class);
//          objectMapper.addMixIn(AuthenticatorTransport.class, AuthenticatorTransportMixIn.class);
			objectMapper.addMixIn(CredProtectAuthenticationExtensionsClientInput.class, CredProtectAuthenticationExtensionsClientInputMixIn.class);
			objectMapper.addMixIn(CredProtect.class, CredProtectMixIn.class);
		}

		return objectMapper;
	}

	public static UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken() {
		return UsernamePasswordAuthenticationToken.authenticated(
			"admin1", "password", List.of(new SimpleGrantedAuthority("ROLE_ADM"))
		);
	}

	public static PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions() {
		return PublicKeyCredentialCreationOptions.builder()
			.rp(PublicKeyCredentialRpEntity.builder().id("example.com").name("Example RP").build())
			.user(ImmutablePublicKeyCredentialUserEntity.builder().name("name").id(Bytes.random()).displayName("displayName").build())
			.challenge(Bytes.random())
			.pubKeyCredParams(List.of(PublicKeyCredentialParameters.ES384, PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.RS512))
			.timeout(Duration.ofSeconds(60))
			.excludeCredentials(Collections.singletonList(
				PublicKeyCredentialDescriptor.builder()
					.id(Bytes.random())
					.type(PublicKeyCredentialType.PUBLIC_KEY)
					.transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
					.build()
			))
			.authenticatorSelection(AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.REQUIRED)
				.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
				.build()
			)
			.attestation(AttestationConveyancePreference.DIRECT)
			.extensions(
				new ImmutableAuthenticationExtensionsClientInputs(new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true)))
			)
			.build();
	}

	public static PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions() {
		return PublicKeyCredentialRequestOptions.builder()
			.challenge(Bytes.random())
			.timeout(Duration.ofSeconds(60))
			.rpId("example.com")
			.allowCredentials(
				List.of(
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
						.build()
				)
			)
			.userVerification(UserVerificationRequirement.PREFERRED)
			.extensions(
				new ImmutableAuthenticationExtensionsClientInputs(
					new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true))
				)
			)
			.build();
	}
}
