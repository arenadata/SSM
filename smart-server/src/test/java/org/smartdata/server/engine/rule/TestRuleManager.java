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
package org.smartdata.server.engine.rule;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.exception.NotFoundException;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.AuditSortField;
import org.smartdata.model.FileInfo;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.request.AuditSearchRequest;
import org.smartdata.security.AnonymousDefaultPrincipalProvider;
import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.security.ThreadScopeSmartPrincipalManager;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.audit.AuditService;

import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertThrows;

/**
 * Testing RuleManager service.
 */
public class TestRuleManager extends TestDaoBase {
  private RuleManager ruleManager;

  @Before
  public void init() throws Exception {
    SmartConf smartConf = new SmartConf();
    ServerContext serverContext = new ServerContext(smartConf, metaStore);
    SmartPrincipalManager principalManager = new ThreadScopeSmartPrincipalManager(
        new AnonymousDefaultPrincipalProvider());
    ruleManager = new RuleManager(serverContext, null,
        null, new NoOpAuditService(), principalManager);
    ruleManager.init();
    ruleManager.start();
  }

  @After
  public void close() throws Exception {
    ruleManager.stop();
    ruleManager = null;
  }

  @Test
  public void testSubmitNewActiveRule() throws Exception {
    String rule = "file: every 1s \n | accessCount(5s) > 3 | cache";
    long id = ruleManager.submitRule(rule, RuleState.ACTIVE);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);
    RuleInfo info = ruleInfo;
    for (int i = 0; i < 5; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }

    Assert.assertTrue(info.getNumChecked()
        - ruleInfo.getNumChecked() > 3);
  }

  @Test
  public void testSubmitDeletedRule() {
    String rule = "file: every 1s \n | length > 300 | cache";
    try {
      ruleManager.submitRule(rule, RuleState.DELETED);
    } catch (Exception e) {
      Assert.assertTrue(e.getMessage().contains("Invalid initState"));
    }
  }

  @Test
  public void testSubmitNewDisabledRule() throws Exception {
    String rule = "file: every 1s \n | length > 300 | cache";
    long id = ruleManager.submitRule(rule, RuleState.DISABLED);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);
    RuleInfo info = ruleInfo;
    for (int i = 0; i < 5; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }

    Assert.assertEquals(0, info.getNumChecked()
        - ruleInfo.getNumChecked());
  }

  @Test
  public void testSubmitAutoEndsRule() throws Exception {
    String rule = "file: every 1s from now to now + 2s \n | "
        + "length > 300 | cache";

    long id = ruleManager.submitRule(rule, RuleState.ACTIVE);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);
    RuleInfo info = ruleInfo;
    for (int i = 0; i < 5; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }

    Assert.assertSame(info.getState(), RuleState.FINISHED);
    Assert.assertTrue(info.getNumChecked()
        - ruleInfo.getNumChecked() <= 3);
  }

  @Test
  public void testDeleteRule() throws Exception {
    String rule = "file: every 1s from now to now + 100s \n | "
        + "length > 300 | cache";

    long id = ruleManager.submitRule(rule, RuleState.ACTIVE);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);

    ruleManager.deleteRule(ruleInfo.getId(), true);

    assertThrows(NotFoundException.class,
        () -> ruleManager.getRuleInfo(ruleInfo.getId()));
  }

  @Test
  public void testResumeRule() throws Exception {
    String rule = "file: every 1s from now to now + 100s \n | "
        + "length > 300 | cache";

    long id = ruleManager.submitRule(rule, RuleState.ACTIVE);
    RuleInfo ruleInfo = ruleManager.getRuleInfo(id);
    Assert.assertEquals(ruleInfo.getRuleText(), rule);
    RuleInfo info = ruleInfo;
    for (int i = 0; i < 2; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }
    Assert.assertTrue(info.getNumChecked()
        > ruleInfo.getNumChecked());

    ruleManager.disableRule(ruleInfo.getId(), true);
    Thread.sleep(1000);
    RuleInfo info2 = ruleManager.getRuleInfo(id);
    for (int i = 0; i < 3; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }
    Assert.assertEquals(info.getNumChecked(), info2.getNumChecked());

    RuleInfo info3 = info;
    ruleManager.activateRule(ruleInfo.getId());
    for (int i = 0; i < 3; i++) {
      Thread.sleep(1000);
      info = ruleManager.getRuleInfo(id);
      System.out.println(info);
    }
    Assert.assertTrue(info.getNumChecked()
        > info3.getNumChecked());
  }

  @Test
  public void testSubmitNewMultiRules() throws Exception {
    String rule = "file: every 1s \n | length > 300 | cache";

    // id increasing
    int nRules = 3;
    long[] ids = new long[nRules];
    for (int i = 0; i < nRules; i++) {
      ids[i] = ruleManager.submitRule(rule, RuleState.DISABLED);
      System.out.println(ruleManager.getRuleInfo(ids[i]));
      if (i > 0) {
        Assert.assertEquals(1, ids[i] - ids[i - 1]);
      }
    }

    for (int i = 0; i < nRules; i++) {
      long ruleId = ids[i];
      ruleManager.deleteRule(ruleId, true);
      assertThrows(NotFoundException.class,
          () -> ruleManager.getRuleInfo(ruleId));
    }

    long[] ids2 = new long[nRules];
    for (int i = 0; i < nRules; i++) {
      ids2[i] = ruleManager.submitRule(rule, RuleState.DISABLED);
      System.out.println(ruleManager.getRuleInfo(ids2[i]));
      if (i > 0) {
        Assert.assertEquals(1, ids2[i] - ids2[i - 1]);
      }
      Assert.assertTrue(ids2[i] > ids[nRules - 1]);
    }

    System.out.println("\nFinal state:");
    List<RuleInfo> allRules = ruleManager.listRulesInfo();
    // Deleted rules are not included in the list
    Assert.assertEquals(allRules.size(), nRules);
    for (RuleInfo info : allRules) {
      System.out.println(info);
    }
  }

  @Test
  public void testMultiThreadUpdate() throws Exception {
    String rule = "file: every 1s \n | length > 10 | cache";

    long now = System.currentTimeMillis();

    long rid = ruleManager.submitRule(rule, RuleState.DISABLED);
    ruleManager.updateRuleInfo(rid, null, now, 1, 1);

    long start = System.currentTimeMillis();

    Thread[] threads = new Thread[] {
        new Thread(new RuleInfoUpdater(rid, 3)),
//        new Thread(new RuleInfoUpdater(rid, 7)),
//        new Thread(new RuleInfoUpdater(rid, 11)),
        new Thread(new RuleInfoUpdater(rid, 17))};

    for (Thread t : threads) {
      t.start();
    }

    for (Thread t : threads) {
      t.join();
    }

    long end = System.currentTimeMillis();
    System.out.println("Time used = " + (end - start) + " ms");

    RuleInfo res = ruleManager.getRuleInfo(rid);
    System.out.println(res);
  }

  private class RuleInfoUpdater implements Runnable {
    private final long ruleId;
    private final int index;

    public RuleInfoUpdater(long ruleId, int index) {
      this.ruleId = ruleId;
      this.index = index;
    }

    @Override
    public void run() {
      long lastCheckTime;
      long checkedCount;
      int cmdletsGen;
      try {
        for (int i = 0; i < 200; i++) {
          RuleInfo info = ruleManager.getRuleInfo(ruleId);
          lastCheckTime = System.currentTimeMillis();
          checkedCount = info.getNumChecked();
          cmdletsGen = (int) info.getNumCmdsGen();
          Assert.assertEquals(checkedCount, cmdletsGen);
          ruleManager.updateRuleInfo(ruleId, null,
              lastCheckTime, index, index);
        }
      } catch (Exception e) {
        Assert.fail("Can not have exception here.");
      }
    }
  }

  @Test
  public void testMultiThreadChangeState() throws Exception {
    String rule = "file: every 1s \n | length > 10 | cache";

    long now = System.currentTimeMillis();

    long length = 100;
    long fid = 10000;
    FileInfo[] files = {new FileInfo("/tmp/testfile", fid, length, false, (short) 3,
        1024, now, now, (short) 1, null, null, (byte) 3, (byte) 0)};

    metaStore.insertFiles(files);
    long rid = ruleManager.submitRule(rule, RuleState.ACTIVE);

    long start = System.currentTimeMillis();

    int nThreads = 2;
    Thread[] threads = new Thread[nThreads];
    for (int i = 0; i < nThreads; i++) {
      threads[i] = new Thread(new StateChangeWorker(rid));
    }

    for (Thread t : threads) {
      t.start();
    }

    for (Thread t : threads) {
      t.join();
    }

    long end = System.currentTimeMillis();
    System.out.println("Time used = " + (end - start) + " ms");
    Thread.sleep(1000); // This is needed due to async threads

    RuleInfo res = ruleManager.getRuleInfo(rid);
    System.out.println(res);
    Thread.sleep(5000);
    RuleInfo after = ruleManager.getRuleInfo(rid);
    System.out.println(after);
    if (res.getState() == RuleState.ACTIVE) {
      Assert.assertTrue(after.getNumCmdsGen() - res.getNumCmdsGen() <= 6);
    } else {
      Assert.assertEquals(after.getNumCmdsGen(), res.getNumCmdsGen());
    }
  }

  private class StateChangeWorker implements Runnable {
    private final long ruleId;

    public StateChangeWorker(long ruleId) {
      this.ruleId = ruleId;
    }

    @Override
    public void run() {
      Random r = new Random();
      try {
        for (int i = 0; i < 200; i++) {
          int rand = r.nextInt() % 2;
          //System.out.println(rand == 0 ? "Active" : "Disable");
          switch (rand) {
            case 0:
              ruleManager.activateRule(ruleId);
              break;
            case 1:
              ruleManager.disableRule(ruleId, true);
              break;
          }
        }
      } catch (Exception e) {
        Assert.fail("Should not happen!");
      }
    }
  }

  private static class NoOpAuditService extends AuditService {

    public NoOpAuditService() {
      super(null);
    }

    @Override
    public void logEvent(UserActivityEvent event) {
    }

    @Override
    public SearchResult<UserActivityEvent> search(
        AuditSearchRequest searchRequest, PageRequest<AuditSortField> pageRequest) {
      return SearchResult.emptyResult();
    }

    @Override
    public List<UserActivityEvent> search(AuditSearchRequest searchRequest) {
      return Collections.emptyList();
    }
  }
}
