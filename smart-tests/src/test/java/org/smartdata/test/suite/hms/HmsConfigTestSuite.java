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

import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.assertj.core.groups.Tuple;
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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static java.lang.String.format;
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

  private static final String TEST_DATABASE = "db1";

  @BeforeMethod
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
    int testTableQuantity = 2;
    createTestDataInHiveMetaStore(testTableQuantity);
    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll()).hasSize(4), DEFAULT_WAIT_PARAMS);
    List<HiveMetastoreEventEntity> events = hiveMetastoreEventDao.findAll();
    List<Long> eventsIds = events.stream()
        .map(HiveMetastoreEventEntity::getId)
        .collect(Collectors.toList());
    assertEventsContainExpectedEntities(events, testTableQuantity);
    containerManager.restart(SSM_SERVER);
    List<HiveMetastoreEventEntity> eventsAfterRestart = hiveMetastoreEventDao.findAll();
    assertEventsContainExpectedEntities(eventsAfterRestart, testTableQuantity);
    assertThat(eventsAfterRestart)
        .extracting(HiveMetastoreEventEntity::getId)
        .doesNotContainAnyElementsOf(eventsIds);
  }

  private void createTestDataInHiveMetaStore(int testTableQuantity) throws Exception {
    hiveRepository.executeSql("create database " + TEST_DATABASE);
    for (int i = 0; i < testTableQuantity; i++) {
      hiveRepository.executeSql(format("create table %s.t%s(i int)", TEST_DATABASE, i));
    }
  }

  private void assertEventsContainExpectedEntities(List<HiveMetastoreEventEntity> events, int testTableQuantity) {
    List<Tuple> expectedEvents = new ArrayList<>();
    expectedEvents.add(tuple("default", "DATABASE", "CREATE"));
    expectedEvents.add(tuple(TEST_DATABASE, "DATABASE", "CREATE"));
    for (int i = 0; i < testTableQuantity; i++) {
      expectedEvents.add(tuple(format("%s.t%s", TEST_DATABASE, i), "TABLE", "CREATE"));
    }
    assertThat(events)
        .extracting(HiveMetastoreEventEntity::getEntityName,
            HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getEventType)
        .containsExactlyInAnyOrder(expectedEvents.toArray(new Tuple[0]));
  }
}
