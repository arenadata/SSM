/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.server.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.Md4PasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

/**
 * Enhanced version of Spring's
 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder}.
 */
public interface PasswordEncoderFactory {

  @RequiredArgsConstructor
  @Getter
  enum EncoderType {
    NOOP("noop"),
    BCRYPT("bcrypt"),
    LDAP("ldap"),
    MD4("md4"),
    MD5("md5"),
    PBKDF2("pbkdf2"),
    SCRYPT("scrypt"),
    SHA_1("sha-1"),
    SHA_256("sha-256");

    private final String id;

    public static EncoderType fromId(String id) {
      for (EncoderType encoderType : EncoderType.values()) {
        if (encoderType.id.equals(id)) {
          return encoderType;
        }
      }
      throw new IllegalArgumentException("Wrong encoder id: " + id);
    }
  }

  @SuppressWarnings("deprecation")
  static PasswordEncoder build(EncoderType defaultEncoderType) {
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put(EncoderType.BCRYPT.id, new BCryptPasswordEncoder());
    encoders.put(EncoderType.LDAP.id, new LdapShaPasswordEncoder());
    encoders.put(EncoderType.MD4.id, new Md4PasswordEncoder());
    encoders.put(EncoderType.MD5.id, new MessageDigestPasswordEncoder("MD5"));
    encoders.put(EncoderType.NOOP.id, NoOpPasswordEncoder.getInstance());
    encoders.put(EncoderType.PBKDF2.id, new Pbkdf2PasswordEncoder());
    encoders.put(EncoderType.SCRYPT.id, new SCryptPasswordEncoder());
    encoders.put(EncoderType.SHA_1.id, new MessageDigestPasswordEncoder("SHA-1"));
    encoders.put(EncoderType.SHA_256.id, new MessageDigestPasswordEncoder("SHA-256"));

    DelegatingPasswordEncoder passwordEncoder =
        new DelegatingPasswordEncoder(defaultEncoderType.id, encoders);
    passwordEncoder.setDefaultPasswordEncoderForMatches(encoders.get(defaultEncoderType.id));
    return passwordEncoder;
  }
}
