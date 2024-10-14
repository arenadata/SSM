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
package org.smartdata.server.util;

import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ConfigKeys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.server.util.ConfigUtils.parsePredefinedUsers;

public class ConfigUtilsTest {

  @Test
  public void testParseNullUsers() {
    List<UserDetails> users = parsePredefinedUsers(new SmartConf());
    assertTrue(users.isEmpty());
  }

  @Test
  public void testParseEmptyUsers() {
    SmartConf conf = new SmartConf();
    conf.set(ConfigKeys.PREDEFINED_USERS, "");

    List<UserDetails> users = parsePredefinedUsers(conf);
    assertTrue(users.isEmpty());
  }

  @Test
  public void testParseSingleUser() {
    SmartConf conf = new SmartConf();
    conf.set(ConfigKeys.PREDEFINED_USERS, "user:pass");

    List<UserDetails> users = parsePredefinedUsers(conf);
    List<UserDetails> expectedUsers = Collections.singletonList(
        buildUser("user", "pass")
    );
    assertEquals(expectedUsers, users);
  }

  @Test
  public void testParseUsers() {
    SmartConf conf = new SmartConf();
    conf.set(ConfigKeys.PREDEFINED_USERS, "admin:admin,user:pass");

    List<UserDetails> users = parsePredefinedUsers(conf);
    List<UserDetails> expectedUsers = Arrays.asList(
        buildUser("admin", "admin"),
        buildUser("user", "pass")
    );

    assertEquals(expectedUsers, users);
  }

  private UserDetails buildUser(String user, String password) {
    return User.withUsername(user)
        .password(password)
        .roles()
        .build();
  }
}
