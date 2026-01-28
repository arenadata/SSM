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
package org.smartdata.test.suite.hms;

import io.arenadata.test.model.UserRole;
import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.entity.HiveMetastoreEventEntity;
import org.smartdata.test.repository.HiveRepository;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.List;
import java.util.stream.Collectors;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;

@Feature("HMS replication")
public class HmsConfigTestSuite extends SsmBaseSuite {

  @Autowired
  private ConfigModifierService configModifierService;

  @Autowired
  private ContainerManager containerManager;

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private HiveRepository hiveRepository;

  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;

  @BeforeMethod
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
  }

  @BeforeMethod(dependsOnMethods = "testPrepare")
  public void cleanConfig() throws Exception {
    configModifierService.restoreOriginalFile("smart-site-master.xml");
    configModifierService.restoreOriginalFile("smart-site-agent.xml");
  }

  @AfterMethod
  public void restoreConfig() throws Exception {
    configModifierService.restoreOriginalFile("smart-site-master.xml");
    configModifierService.restoreOriginalFile("smart-site-agent.xml");
  }

  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.sync.full=true")
  public void testHiveEventSyncFullTrue() throws Exception {
    configModifierService.addProperty("smart-site-master.xml", "smart.hive.event.sync.full", "true");
    containerManager.restart(SSM_SERVER);
    hiveRepository.executeSql("create database db1");
    hiveRepository.executeSql("create table db1.t1(i int)");
    hiveRepository.executeSql("create table db1.t2(i int)");
    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll()).hasSize(4), DEFAULT_WAIT_PARAMS);
    List<HiveMetastoreEventEntity> events = hiveMetastoreEventDao.findAll();
    List<Long> eventsIds = hiveMetastoreEventDao.findAll().stream()
        .map(HiveMetastoreEventEntity::getId)
        .collect(Collectors.toList());
    assertThat(events)
        .extracting(HiveMetastoreEventEntity::getEntityName, HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getEventType)
        .containsExactlyInAnyOrder(
            tuple("default", "DATABASE", "CREATE"),
            tuple("db1", "DATABASE", "CREATE"),
            tuple("db1.t1", "TABLE", "CREATE"),
            tuple("db1.t2", "TABLE", "CREATE"));
    containerManager.restart(SSM_SERVER);
    List<HiveMetastoreEventEntity> eventsAfterRestart = hiveMetastoreEventDao.findAll();
    assertThat(eventsAfterRestart)
        .extracting(HiveMetastoreEventEntity::getEntityName, HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getEventType)
        .containsExactlyInAnyOrder(
            tuple("default", "DATABASE", "CREATE"),
            tuple("db1", "DATABASE", "CREATE"),
            tuple("db1.t1", "TABLE", "CREATE"),
            tuple("db1.t2", "TABLE", "CREATE"));
    assertThat(eventsAfterRestart)
        .extracting(HiveMetastoreEventEntity::getId)
        .doesNotContainAnyElementsOf(eventsIds);
  }
}
