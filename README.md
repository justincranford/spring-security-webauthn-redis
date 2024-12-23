# Overview

Demonstrate the bugs I encountered trying to get
Spring Security 6.4.1 WebAuthn classes to serialize and deserialize
in a RedisSessionRepository.

I included ITs and UTs to reproduce issues, and show incremental workarounds
I applied until I got something working.

# Summary

1. Issue: Redis [defaultSerializer](https://github.com/spring-projects/spring-session/blob/a2efffe9bc6122f9f31a1192d704589970a5de84/spring-session-data-redis/src/main/java/org/springframework/session/data/redis/RedisIndexedSessionRepository.java#L324) can't serialize Spring Security WebAuthn [PublicKeyCredentialCreationOptions.java](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/api/PublicKeyCredentialCreationOptions.java#L35) and [PublicKeyCredentialRequestOptions](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/api/PublicKeyCredentialRequestOptions.java#L35), because they don't implement the Serializable interface.
2. Issue: [SecurityJackson2Modules.getModules](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/core/src/main/java/org/springframework/security/jackson2/SecurityJackson2Modules.java#L76-L91) does not include `WebauthnJackson2Module`, even though the name and package imply it is a Spring Security Jackson2 module.
3. Issue: [WebauthnJackson2Module](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/jackson/WebauthnJackson2Module.java#L60) is missing some MixIns, and some MixIns are missing fields.
4. Issue: `SecurityJackson2Modules` seems to override typing, which causes an issue. Applying a laisse faire override helped, but I don't think that is the best workaround, so I would like to understand how to fix.
5. Issue: `SecurityJackson2Modules` supports [UnmodifiableRandomAccessList](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/core/src/main/java/org/springframework/security/jackson2/SecurityJackson2Modules.java#L236) which serializes OK, but doesn't deserialize OK; it leaves trailing tokens.
6. Issue: Please help me apply my custom [RedisHttpSessionConfiguration](https://github.com/justincranford/spring-security-webauthn-redis/blob/d953cff6395604a7cece9d0651d45a79ec3eb439/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L234). I want to use my custom `MySessionIdGenerator`, but I can't figure out how to apply my custom config.

# Details

1. Issue: Redis [defaultSerializer](https://github.com/spring-projects/spring-session/blob/a2efffe9bc6122f9f31a1192d704589970a5de84/spring-session-data-redis/src/main/java/org/springframework/session/data/redis/RedisIndexedSessionRepository.java#L324) can't serialize Spring Security WebAuthn [PublicKeyCredentialCreationOptions.java](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/api/PublicKeyCredentialCreationOptions.java#L35) and [PublicKeyCredentialRequestOptions](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/api/PublicKeyCredentialRequestOptions.java#L35), because they don't implement the Serializable interface.

Reproduced in [`src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisDefaultSerializerIT.java`](src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisDefaultSerializerIT.java).

Workaround was to override default RedisSerializer from `JdkSerializationRedisSerializer` to `GenericJackson2JsonRedisSerializer`.

## Workaround to use `GenericJackson2JsonRedisSerializer`

ObjectMapper instances, with various incremental workarounds, are created in:
[src/test/java/com/justincranford/springsecurity/webauthn/redis/util/ObjectMapperFactory.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/ObjectMapperFactory.java)
 
ObjectMapper instances are injected into Redis Configuration classes to demonstrate each incremental workaround, until enough workarounds are applied to make Redis serialize Spring Security WebAuthn classes OK.
[src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java).

Workaround snippet:
```java
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
    objectMapper.registerModules(org.springframework.security.jackson2.SecurityJackson2Modules.getModules(CLASS_LOADER));
```

N.B. The last line above adds MixIns needed for two classes typically used in SecurityContext.
```java
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
```


2. Issue: [SecurityJackson2Modules.getModules](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/core/src/main/java/org/springframework/security/jackson2/SecurityJackson2Modules.java#L76-L91) does not include `WebauthnJackson2Module`, even though the name and package imply it is a Spring Security Jackson2 module.

Workaround is to register WebauthnJackson2Module myself:
```java
    objectMapper.registerModule(new WebauthnJackson2Module());
```

3. Issue: [WebauthnJackson2Module](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/web/src/main/java/org/springframework/security/web/webauthn/jackson/WebauthnJackson2Module.java#L60) is missing some MixIns, and some MixIns are missing fields.

Workaround is to add 13 of my own mixins after registering `WebauthnJackson2Module`.

Test instances of `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions` are available from [src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyGivens.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyGivens.java).

Snippet of registering 13 of my own MixIns implemented in [src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyWebauthnMixins.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyWebauthnMixins.java).
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

4. Issue: `SecurityJackson2Modules` seems to override typing, which causes an issue. Applying a laisse faire override helped, but I don't think that is the best workaround, so I would like to understand how to fix.

See [https://github.com/justincranford/spring-security-webauthn-redis/blob/c131d7f8d975d228021834ff79fbafae992a39a7/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L130](https://github.com/justincranford/spring-security-webauthn-redis/blob/c131d7f8d975d228021834ff79fbafae992a39a7/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L130)
for the issue:
```text
Could not read JSON:The class with java.util.ImmutableCollections$ListN and name of java.util.ImmutableCollections$ListN is not in the allowlist. If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin. If the serialization is only done by a trusted source, you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details (through reference chain: org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions[\"pubKeyCredParams\"])
```

Workaround is override default typing after registering `SecurityJackson2Modules.getModules`.
```java
    objectMapper.activateDefaultTyping(
        LaissezFaireSubTypeValidator.instance,
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY
    );
```

5. Issue: `SecurityJackson2Modules` supports [UnmodifiableRandomAccessList](https://github.com/spring-projects/spring-security/blob/fd267dfb71bfc8e1ab5bcc8270c12fbaad46fddf/core/src/main/java/org/springframework/security/jackson2/SecurityJackson2Modules.java#L236) which serializes OK, but doesn't deserialize OK; it leaves trailing tokens.

Workaround: `Set DeserializationFeature.FAIL_ON_TRAILING_TOKENS` to false.
```java
    // Relax deserialization to handle this cryptic Collections$UnmodifiableRandomAccessList nested serialization:
    //    "authorities" : [ "java.util.Collections$UnmodifiableRandomAccessList", [ {
    //      "@class" : "org.springframework.security.core.authority.SimpleGrantedAuthority",
    //      "authority" : "ROLE_ADM"
    //    } ] ],
    objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);
```

6. Issue: Please help me apply my custom [RedisHttpSessionConfiguration](https://github.com/justincranford/spring-security-webauthn-redis/blob/d953cff6395604a7cece9d0651d45a79ec3eb439/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L234). I want to use my custom `MySessionIdGenerator`, but I can't figure out how to apply my custom config.

If you could provide guidance that would be great. I couldn't find how to override default config in any official docs.

If you could provide a pointer to source class where an override is applied, that would also be helpful.
