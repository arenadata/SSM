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
package org.smartdata.server.engine.audit;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.request.AuditSearchRequest;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipal;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.ServerContext;

import java.util.Collections;
import java.util.List;

import static org.smartdata.model.audit.UserActivityObject.RULE;
import static org.smartdata.model.audit.UserActivityOperation.CREATE;
import static org.smartdata.model.audit.UserActivityOperation.DELETE;
import static org.smartdata.model.audit.UserActivityOperation.START;
import static org.smartdata.model.audit.UserActivityOperation.STOP;
import static org.smartdata.model.audit.UserActivityResult.FAILURE;
import static org.smartdata.model.audit.UserActivityResult.SUCCESS;

public class TestRuleLifecycleLogger extends TestDaoBase {
  private RuleManager ruleManager;
  private AuditService auditService;
  private SmartPrincipalManager principalManager;

  @Before
  public void init() throws Exception {
    SmartConf smartConf = new SmartConf();
    ServerContext serverContext = new ServerContext(smartConf, metaStore);

    auditService = new AuditService(metaStore.userActivityDao());
    principalManager = new ThreadScopeSmartPrincipalManager(
        new AnonymousDefaultPrincipalProvider());

    ruleManager = new RuleManager(
        serverContext, null, null, auditService, principalManager);
    ruleManager.init();
    ruleManager.start();
  }

  @After
  public void close() throws Exception {
    ruleManager.stop();
  }

  @Test
  public void testSuccessfullySubmitRule() throws Exception {
    String rule = "file: every 1s \n | accessCount(5s) > 3 | cache";
    long id = ruleManager.submitRule(rule, RuleState.DISABLED);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);

    List<UserActivityEvent> ruleEvents = findRuleEvents(id);
    Assert.assertEquals(1, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(0);
    Assert.assertEquals(CREATE, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testSubmitRuleWithError() throws Exception {
    String rule = "wrong syntax rule";
    try {
      ruleManager.submitRule(rule, RuleState.DISABLED);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> ruleEvents = auditService.search(AuditSearchRequest.empty());
    Assert.assertEquals(1, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(0);
    Assert.assertEquals(CREATE, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testStartRuleWithError() throws Exception {
    try {
      // unknown id
      ruleManager.activateRule(777L);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> ruleEvents = findRuleEvents(777L);
    Assert.assertEquals(1, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(0);
    Assert.assertEquals(START, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testSuccessfullyStopRule() throws Exception {
    String rule = "file: every 1s \n | accessCount(5s) > 3 | cache";
    long id = ruleManager.submitRule(rule, RuleState.DISABLED);

    ruleManager.disableRule(id, false);

    List<UserActivityEvent> ruleEvents = findRuleEvents(id);
    Assert.assertEquals(2, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(1);
    Assert.assertEquals(STOP, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testStopRuleWithError() throws Exception {
    try {
      // unknown id
      ruleManager.disableRule(777L, false);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> ruleEvents = findRuleEvents(777L);
    Assert.assertEquals(1, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(0);
    Assert.assertEquals(STOP, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testSuccessfullyDeleteRule() throws Exception {
    String rule = "file: every 1s \n | accessCount(5s) > 3 | cache";
    long id = ruleManager.submitRule(rule, RuleState.DISABLED);

    ruleManager.deleteRule(id, false);

    List<UserActivityEvent> ruleEvents = findRuleEvents(id);
    Assert.assertEquals(2, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(1);
    Assert.assertEquals(DELETE, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testDeleteRuleWithError() throws Exception {
    try {
      // unknown id
      ruleManager.deleteRule(777L, false);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> ruleEvents = findRuleEvents(777L);
    Assert.assertEquals(1, ruleEvents.size());

    UserActivityEvent event = ruleEvents.get(0);
    Assert.assertEquals(DELETE, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testLogCurrentUser() throws Exception {
    assertEventUsername(AnonymousDefaultPrincipalProvider.anonymousPrincipal());

    SmartPrincipal currentPrincipal = new SmartPrincipal("user1");
    principalManager.setCurrentPrincipal(currentPrincipal);
    assertEventUsername(currentPrincipal);

    principalManager.unsetCurrentPrincipal();
    assertEventUsername(AnonymousDefaultPrincipalProvider.anonymousPrincipal());
  }

  private void assertEventUsername(SmartPrincipal expectedPrincipal) throws Exception {
    String rule = "file: every 1s \n | accessCount(5s) > 3 | cache";
    long id = ruleManager.submitRule(rule, RuleState.DISABLED);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);

    List<UserActivityEvent> cmdletEvents = findRuleEvents(ruleInfo.getId());
    Assert.assertEquals(1, cmdletEvents.size());
    Assert.assertEquals(
        expectedPrincipal.getName(),
        cmdletEvents.get(0).getUsername());
  }

  private List<UserActivityEvent> findRuleEvents(long ruleId) throws Exception {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .objectIds(Collections.singletonList(ruleId))
        .objectTypes(Collections.singletonList(RULE))
        .build();

    return auditService.search(searchRequest);
  }
}
