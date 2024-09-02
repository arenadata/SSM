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
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.request.AuditSearchRequest;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipal;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.cmdlet.CmdletDispatcherHelper;

import java.util.Collections;
import java.util.List;

import static org.smartdata.model.audit.UserActivityObject.CMDLET;
import static org.smartdata.model.audit.UserActivityOperation.DELETE;
import static org.smartdata.model.audit.UserActivityOperation.START;
import static org.smartdata.model.audit.UserActivityOperation.STOP;
import static org.smartdata.model.audit.UserActivityResult.FAILURE;
import static org.smartdata.model.audit.UserActivityResult.SUCCESS;

public class TestCmdletLifecycleLogger extends TestDaoBase {
  private CmdletManager cmdletManager;
  private AuditService auditService;
  private SmartPrincipalManager principalManager;

  @Before
  public void init() throws Exception {
    SmartConf smartConf = new SmartConf();
    ServerContext serverContext = new ServerContext(smartConf, metaStore);

    auditService = new AuditService(metaStore.userActivityDao());
    principalManager = new ThreadScopeSmartPrincipalManager(
        new AnonymousDefaultPrincipalProvider());

    CmdletDispatcherHelper.init();
    cmdletManager = new CmdletManager(serverContext, auditService, principalManager);
    cmdletManager.init();
    cmdletManager.start();
  }

  @After
  public void close() throws Exception {
    cmdletManager.stop();
  }

  @Test
  public void testSuccessfullySubmitCmdlet() throws Exception {
    String cmdlet = "cache -file /testCacheFile";
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet(cmdlet);

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(cmdletInfo.getId());
    Assert.assertEquals(1, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(0);
    Assert.assertEquals(START, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testSubmitCmdletWithError() throws Exception {
    String cmdlet = "wrong syntax cmdlet";
    try {
      cmdletManager.submitCmdlet(cmdlet);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> cmdletEvents = auditService.search(AuditSearchRequest.empty());
    Assert.assertEquals(1, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(0);
    Assert.assertEquals(START, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testSuccessfullyStopCmdlet() throws Exception {
    String cmdlet = "cache -file /testCacheFile";
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet(cmdlet);

    cmdletManager.disableCmdlet(cmdletInfo.getId());

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(cmdletInfo.getId());
    Assert.assertEquals(2, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(1);
    Assert.assertEquals(STOP, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testStopCmdletWithError() throws Exception {
    long nonExistingCmdletId = 777L;
    try {
      cmdletManager.disableCmdlet(nonExistingCmdletId);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(nonExistingCmdletId);
    Assert.assertEquals(1, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(0);
    Assert.assertEquals(STOP, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testSuccessfullyDeleteCmdlet() throws Exception {
    String cmdlet = "cache -file /testCacheFile";
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet(cmdlet);

    cmdletManager.deleteCmdlet(cmdletInfo.getId());

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(cmdletInfo.getId());
    Assert.assertEquals(2, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(1);
    Assert.assertEquals(DELETE, event.getOperation());
    Assert.assertEquals(SUCCESS, event.getResult());
  }

  @Test
  public void testDeleteCmdletWithError() throws Exception {
    long nonExistingCmdletId = 777L;
    try {
      cmdletManager.deleteCmdlet(nonExistingCmdletId);
    } catch (Exception ignore) {
    }

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(nonExistingCmdletId);
    Assert.assertEquals(1, cmdletEvents.size());

    UserActivityEvent event = cmdletEvents.get(0);
    Assert.assertEquals(DELETE, event.getOperation());
    Assert.assertEquals(FAILURE, event.getResult());
  }

  @Test
  public void testLogCurrentUser() throws Exception {
    assertEventUsername(AnonymousDefaultPrincipalProvider.anonymousPrincipal(), "file1");

    SmartPrincipal currentPrincipal = new SmartPrincipal("user1");
    principalManager.setCurrentPrincipal(currentPrincipal);
    assertEventUsername(currentPrincipal, "file2");

    principalManager.unsetCurrentPrincipal();
    assertEventUsername(AnonymousDefaultPrincipalProvider.anonymousPrincipal(), "file3");
  }

  private void assertEventUsername(
      SmartPrincipal expectedPrincipal, String file) throws Exception {
    CmdletInfo cmdletInfo = cmdletManager.submitCmdlet("read -file" + file);

    List<UserActivityEvent> cmdletEvents = findCmdletEvents(cmdletInfo.getId());
    Assert.assertEquals(1, cmdletEvents.size());
    Assert.assertEquals(
        expectedPrincipal.getName(),
        cmdletEvents.get(0).getUsername());
  }

  private List<UserActivityEvent> findCmdletEvents(long cmdletId) throws Exception {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .objectIds(Collections.singletonList(cmdletId))
        .objectTypes(Collections.singletonList(CMDLET))
        .build();

    return auditService.search(searchRequest);
  }
}
