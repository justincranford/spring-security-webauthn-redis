# Overview
Demonstrate all the customizations and workarounds I had to perform to get
Spring Security 6.4.1 WebAuthn classes to serialize and deserialize in a RedisSessionRepository.

# Important classes
1. MyGivens
2. MySessionIdGenerator
3. ObjectMapperFactory
4. MyWebauthnMixins
5. WebauthnMixinsTest
6. WebauthnMixinsIT

# Details

2. Bug Workaround: Implement Jackson2 JSON serialization, because RedisSerializer default is JDK serialization, but WebAuthn API classes are missing Serializable interface.

3. Customization: Register Jackson2 modules for Spring Security, to register mixins such as SimpleGrantedAuthority.
```java
objectMapper.registerModules(org.springframework.security.jackson2.SecurityJackson2Modules.getModules(CLASS_LOADER));
```

3. Bug Workaround: Add Jackson2 module for Spring Security WebAuthn, because it is missing from `SecurityJackson2Modules.getModules`
```java
org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module
```

4. Bug Workaround: Add my extra Jackson2 mixins for Spring Security WebAuthn, because WebauthnJackson2Module is missing mixins for these classes.
```java
			objectMapper.addMixIn(PublicKeyCredentialCreationOptions.class, PublicKeyCredentialCreationOptionsMixIn.class);
			objectMapper.addMixIn(ImmutablePublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialRpEntity.class, PublicKeyCredentialRpEntityMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialParameters.class, PublicKeyCredentialParametersMixIn.class);
			objectMapper.addMixIn(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixIn.class);

			objectMapper.addMixIn(PublicKeyCredentialRequestOptions.class, PublicKeyCredentialRequestOptionsMixIn.class);
			objectMapper.addMixIn(ImmutableAuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
			objectMapper.addMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
			objectMapper.addMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixIn.class);
			objectMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixIn.class);
			objectMapper.addMixIn(CredProtectAuthenticationExtensionsClientInput.class, CredProtectAuthenticationExtensionsClientInputMixIn.class);
			objectMapper.addMixIn(CredProtect.class, CredProtectMixIn.class);
```

Classes
```java
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
```
