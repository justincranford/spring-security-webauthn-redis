# Overview

Demonstrate the bugs I encountered trying to get
Spring Security 6.4.1 WebAuthn classes to serialize and deserialize
in a RedisSessionRepository.

Includes all of the workarounds I added to get it running.

# Issues

1. Issue: Redis DefaultSerializer can't serialize Spring Security WebAuthn `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions`, because they won't implement the Serializable interface.
2. Issue: `SecurityJackson2Modules.getModules` does not include `org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module`
3. Issue: `WebauthnJackson2Module` does not include MixIns for at least 13 classes.
4. Issue: I think registering `SecurityJackson2Modules.getModules` is overriding typing and causing an issue, but I don't fully understand how or why it is breaking.
5. Issue: `WebauthnJackson2Module` includes a Mixin for UnmodifiableRandomAccessList, but it causes training token issue.
6. Issue: Can't figure out how to apply my `RedisHttpSessionConfiguration` with custom `MySessionIdGenerator`.

# Details

1. Issue: Redis DefaultSerializer can't serialize Spring Security WebAuthn `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions`, because they won't implement the Serializable interface.

Reproduced in [`src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisDefaultSerializerIT.java`](src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisDefaultSerializerIT.java).

Workaround was to override default RedisSerializer from `JdkSerializationRedisSerializer` to `GenericJackson2JsonRedisSerializer`.

ObjectMapper instance created in:
[src/test/java/com/justincranford/springsecurity/webauthn/redis/util/ObjectMapperFactory.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/ObjectMapperFactory.java)
 
ObjectMapper instance injected into Redis Configuration classes to verify if it works.
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

The last line registered MixIns needed to persist contents of SecurityContext.
```java
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
```


2. Issue: `SecurityJackson2Modules.getModules` does not include `org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module`

Workaround is to register WebauthnJackson2Module myself:
```java
    objectMapper.registerModule(new WebauthnJackson2Module());
```

3. Issue: `WebauthnJackson2Module` does not include MixIns for at least 13 classes.

Workaround is to add my 13 of my own mixins.

See [src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyGivens.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyGivens.java) for
test instances of PublicKeyCredentialCreationOptions and PublicKeyCredentialRequestOptions.

Snippet of registering my own MixIns implemented in [src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyWebauthnMixins.java](src/test/java/com/justincranford/springsecurity/webauthn/redis/util/MyWebauthnMixins.java).
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

4. Issue: I think registering `SecurityJackson2Modules.getModules` is overriding typing and causing an issue, but I don't fully understand how or why it is breaking.

Workaround is override default typing after registering `SecurityJackson2Modules.getModules`.
```java
    objectMapper.activateDefaultTyping(
        LaissezFaireSubTypeValidator.instance,
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY
    );
```

5. Issue: `WebauthnJackson2Module` includes a Mixin for UnmodifiableRandomAccessList, but it causes training token issue.

Workaround: `Set DeserializationFeature.FAIL_ON_TRAILING_TOKENS` to false.
```java
    // Relax deserialization to handle this cryptic Collections$UnmodifiableRandomAccessList nested serialization:
    //    "authorities" : [ "java.util.Collections$UnmodifiableRandomAccessList", [ {
    //      "@class" : "org.springframework.security.core.authority.SimpleGrantedAuthority",
    //      "authority" : "ROLE_ADM"
    //    } ] ],
    objectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);
```

6. Issue: Can't figure out how to apply my `RedisHttpSessionConfiguration` with custom `MySessionIdGenerator`.

See [https://github.com/justincranford/spring-security-webauthn-redis/blob/d953cff6395604a7cece9d0651d45a79ec3eb439/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L234](https://github.com/justincranford/spring-security-webauthn-redis/blob/d953cff6395604a7cece9d0651d45a79ec3eb439/src/test/java/com/justincranford/springsecurity/webauthn/redis/WebauthnRedisObjectMapperSerializerIT.java#L234)

If you could provide guidance that would be great. I couldn't find how to override default config in any official docs.

If you could provide a pointer to source class where an override is applied, that would also be helpful.