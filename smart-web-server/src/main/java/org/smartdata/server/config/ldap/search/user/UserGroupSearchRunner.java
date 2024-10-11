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
package org.smartdata.server.config.ldap.search.user;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.LdapSearchTemplateFactory;
import org.smartdata.server.config.ldap.search.group.SsmLdapGroupSearch;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import javax.naming.Name;

import java.util.List;

@Slf4j
public class UserGroupSearchRunner extends UserSearchRunner {
  private final SsmLdapGroupSearch groupSearchRunner;
  private final LdapSearchTemplateFactory groupSearchTemplateFactory;

  public UserGroupSearchRunner(
      BaseLdapPathContextSource contextSource,
      LdapSearchTemplateFactory groupSearchTemplateFactory,
      SsmLdapGroupSearch groupSearchRunner,
      SmartConf conf) {
    this(contextSource, new UserSearchByNameAttributeFactory(conf),
        groupSearchTemplateFactory, groupSearchRunner, conf);
  }

  public UserGroupSearchRunner(
      BaseLdapPathContextSource contextSource,
      LdapSearchTemplateFactory userSearchTemplateFactory,
      LdapSearchTemplateFactory groupSearchTemplateFactory,
      SsmLdapGroupSearch groupSearchRunner,
      SmartConf conf) {
    super(contextSource, userSearchTemplateFactory, conf);

    Assert.notNull(groupSearchTemplateFactory,
        "groupSearchTemplateFactory shouldn't be null");
    Assert.notNull(groupSearchRunner, "groupSearchRunner shouldn't be null");

    this.groupSearchTemplateFactory = groupSearchTemplateFactory;
    this.groupSearchRunner = groupSearchRunner;
  }

  @Override
  public DirContextOperations searchForUser(String username) throws UsernameNotFoundException {
    DirContextOperations user = super.searchForUser(username);

    List<Name> groupDns = groupSearchRunner.getGroupDns(
        groupSearchTemplateFactory.buildSearchTemplate(),
        LdapUtils.prepend(user.getDn(), contextSource.getBaseLdapName()));

    if (groupDns.isEmpty()) {
      throw new UsernameNotFoundException("User " + username + " not found in directory.");
    }

    return user;
  }
}
