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
package org.smartdata.integration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.ActionDto;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.client.generated.model.CmdletDto;
import org.smartdata.client.generated.model.CmdletStateDto;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.CmdletsApiWrapper;
import org.smartdata.integration.cluster.SmartCluster;
import org.smartdata.integration.cluster.SmartMiniCluster;
import org.smartdata.metastore.MetaStore;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.server.SmartServer;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.smartdata.metastore.utils.MetaStoreUtils.getDBAdapter;

public class TestCmdletsRestart {
  private SmartCluster cluster;
  private SmartConf conf;
  private CmdletsApiWrapper cmdletsApiClient;
  private ActionsApiWrapper actionsApiWrapper;

  @Before
  public void setup() throws Exception {
    cluster = new SmartMiniCluster();
    conf = new SmartConf();
    cluster.setUp(conf);

    conf.setLong(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_KEY, 100);

    cmdletsApiClient = new CmdletsApiWrapper();
    actionsApiWrapper = new ActionsApiWrapper();
  }

  @After
  public void cleanUp() throws Exception {
    if (cluster != null) {
      cluster.cleanUp();
    }
  }

  @Test
  public void testExecutingCmdletRestartAfterFailure() throws Exception {
    long cmdletId = 22L;
    long actionId = 77L;

    testCmdletRestartAfterFailure(
        createTestCmdlet(cmdletId, CmdletState.EXECUTING, actionId),
        createTestAction(actionId, cmdletId)
    );
  }

  @Test
  public void testPendingCmdletRestartAfterFailure() throws Exception {
    long cmdletId = 1L;
    long actionId = 2L;

    testCmdletRestartAfterFailure(
        createTestCmdlet(cmdletId, CmdletState.PENDING, actionId),
        createTestAction(actionId, cmdletId)
    );
  }

  @Test
  public void testDispatchedCmdletRestartAfterFailure() throws Exception {
    long cmdletId = 2L;
    long actionId = 1L;

    testCmdletRestartAfterFailure(
        createTestCmdlet(cmdletId, CmdletState.DISPATCHED, actionId),
        createTestAction(actionId, cmdletId)
    );
  }

  @Test
  public void testMixedCmdletsRestartAfterFailure() throws Exception {
    List<CmdletInfo> cmdlets = Arrays.asList(
        createTestCmdlet(1L, CmdletState.PENDING, 1L),
        createTestCmdlet(2L, CmdletState.DISPATCHED, 2L),
        createTestCmdlet(3L, CmdletState.EXECUTING, 3L),
        createTestCmdlet(4L, CmdletState.FAILED, 4L),
        createTestCmdlet(5L, CmdletState.CANCELLED, 5L)
    );

    List<ActionInfo> actions = IntStream.range(1, cmdlets.size() + 1)
        .mapToObj(id -> createTestAction(id, id))
        .collect(Collectors.toList());

    actions.get(3).setFinished(true);
    actions.get(4).setFinished(true);

    MetaStore metaStore = initMetastore(cmdlets, actions);
    try (SmartServer smartServer = new SmartServer(conf, metaStore)) {
      smartServer.run();

      IntStream.range(1, 4)
          .peek(this::checkCmdletDone)
          .forEach(this::checkActionDone);

      assertEquals(CmdletStateDto.FAILED, cmdletsApiClient.getCmdlet(4L).getState());
      assertEquals(CmdletStateDto.CANCELLED, cmdletsApiClient.getCmdlet(5L).getState());

      assertEquals(ActionStateDto.FAILED, actionsApiWrapper.getAction(4L).getState());
      assertEquals(ActionStateDto.FAILED, actionsApiWrapper.getAction(5L).getState());
    }
  }

  private void testCmdletRestartAfterFailure(
      CmdletInfo cmdletInfo, ActionInfo... actionInfos) throws Exception {
    MetaStore metaStore = initMetastore(
        Collections.singletonList(cmdletInfo), Arrays.asList(actionInfos));

    try (SmartServer smartServer = new SmartServer(conf, metaStore)) {
      smartServer.run();
      checkCmdletDone(cmdletInfo.getId());
      for (ActionInfo actionInfo : actionInfos) {
        checkActionDone(actionInfo.getActionId());
      }
    }
  }

  private MetaStore initMetastore(
      List<CmdletInfo> cmdletsToStore,
      List<ActionInfo> actionsToStore) throws Exception {
    MetaStore metaStore = getDBAdapter(new SmartConf());
    metaStore.checkTables();

    metaStore.cmdletDao().upsert(cmdletsToStore);
    metaStore.actionDao().upsert(actionsToStore);

    return metaStore;
  }

  private void checkCmdletDone(long cmdletId) {
    CmdletDto cmdletDto = cmdletsApiClient.waitTillCmdletFinished(
        cmdletId,
        Duration.ofMillis(500),
        Duration.ofSeconds(5));
    assertEquals(CmdletStateDto.DONE, cmdletDto.getState());
  }

  private void checkActionDone(long actionId) {
    ActionDto actionDto = actionsApiWrapper.waitTillActionFinished(
        actionId,
        Duration.ofMillis(500),
        Duration.ofSeconds(5));
    assertEquals(ActionStateDto.SUCCESSFUL, actionDto.getState());
  }

  private CmdletInfo createTestCmdlet(long id, CmdletState state, Long... actionIds) {
    return CmdletInfo.builder()
        .setId(id)
        .setState(state)
        .setParameters("write -file /test" + id)
        .setActionIds(Arrays.asList(actionIds))
        .setGenerateTime(System.currentTimeMillis())
        .build();
  }

  private ActionInfo createTestAction(long id, long cmdletId) {
    Map<String, String> actionArgs = new HashMap<>();
    actionArgs.put("-file", "/test" + cmdletId);

    return ActionInfo.builder()
        .setActionId(id)
        .setCmdletId(cmdletId)
        .setActionName("write")
        .setCreateTime(System.currentTimeMillis())
        .setArgs(actionArgs)
        .build();
  }
}
