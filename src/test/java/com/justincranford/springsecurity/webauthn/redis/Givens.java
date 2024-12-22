package com.justincranford.springsecurity.webauthn.redis;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
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
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Givens {
	public static ObjectMapper objectMapper() {
		return new ObjectMapper()
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
