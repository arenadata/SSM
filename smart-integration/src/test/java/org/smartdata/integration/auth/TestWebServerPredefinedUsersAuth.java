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
package org.smartdata.integration.auth;

import org.junit.runners.Parameterized.Parameters;
import org.smartdata.conf.SmartConf;

import static org.smartdata.integration.auth.TestWebServerAuth.TestParams.ExpectedResult.FAIL;
import static org.smartdata.server.config.ConfigKeys.PREDEFINED_BASIC_AUTH_ENABLED;
import static org.smartdata.server.config.ConfigKeys.PREDEFINED_USERS;
import static org.smartdata.server.config.ConfigKeys.PREDEFINED_USERS_PASSWORD_ENCODER;

public class TestWebServerPredefinedUsersAuth extends TestWebServerAuth {

  @Parameters(name = "{0}")
  public static TestParams[] parameters() {
    return new TestParams[]{
        new TestParams("user1", "pass1", plainTextCredentials()),
        new TestParams("user2", "pass2", plainTextCredentials()),
        new TestParams("unknown", "pass", plainTextCredentials(), FAIL),
        new TestParams("user1", "pass1", bcryptCredentials()),
        new TestParams("unknown2", "unknown", bcryptCredentials(), FAIL),
        new TestParams("user2", "pass2", pbkdf2Credentials()),
        new TestParams("unknown3", "unknown2", pbkdf2Credentials(), FAIL),
        new TestParams("user1", "pass1", hashCredentialsWithDefaultEncoder()),
        new TestParams("user2", "pass2", hashCredentialsWithDefaultEncoder(), FAIL)
    };
  }

  private static SmartConf plainTextCredentials() {
    SmartConf conf = baseConf();
    conf.set(PREDEFINED_USERS, "user1:pass1,user2:pass2");

    conf.set(TEST_PARAM_NAME_OPTION, "plainTextCredentials");
    return conf;
  }

  private static SmartConf bcryptCredentials() {
    SmartConf conf = baseConf();
    conf.set(PREDEFINED_USERS,
        // user1:pass1
        "user1:{bcrypt}$2a$10$.E/VDhdRt85NyN7/kzrE8uCVu6Ey3tbGR/efyOOIgw.e4BeYcb8.G,"
            // user2:pass2
            + "user2:{bcrypt}$2a$10$kEZuKAa9sL3C2YlTwSo7meNfvjkZMHGUkf6T/E6.eSO6.OIt.Q9qa");

    conf.set(TEST_PARAM_NAME_OPTION, "bcryptCredentials");
    return conf;
  }

  private static SmartConf pbkdf2Credentials() {
    SmartConf conf = baseConf();
    // user1:pass1
    conf.set(PREDEFINED_USERS, "user1:{pbkdf2}"
        + "8d831f4f23dc4f0f43bdabd573372c6ea091f8fb55cb7d0242534d35f7fe14bb932da695a20c3c23,"
        // user2:pass2
        + "user2:{pbkdf2}"
        + "b4f2a5e4a827e83fae4346e2ffc806ee61a79ff40aeea3afea7acac2d6651fe17869968c55902618");

    conf.set(TEST_PARAM_NAME_OPTION, "pbkdf2Credentials");
    return conf;
  }

  private static SmartConf hashCredentialsWithDefaultEncoder() {
    SmartConf conf = baseConf();
    // user1:pass1
    conf.set(PREDEFINED_USERS, "user1:$e0801$LBsB5RY9rXDw343mFrViv74uFhi6SRqE5R8KirZjIcDd966x"
        + "TJbzrDVgtgnFAX8h+zU+6+raIsPnckqF4D7Smg=="
        + "$l72uGTcby92qvT6vd+gekAjUL/WJSDvujf///s/l+sQ=");
    conf.set(PREDEFINED_USERS_PASSWORD_ENCODER, "scrypt");

    conf.set(TEST_PARAM_NAME_OPTION, "hashCredentialsWithDefaultEncoder");
    return conf;
  }

  private static SmartConf baseConf() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(PREDEFINED_BASIC_AUTH_ENABLED, true);
    return conf;
  }
}
