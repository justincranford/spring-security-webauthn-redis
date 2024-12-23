package com.justincranford.springsecurity.webauthn.redis.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public final class MyGivens {
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
