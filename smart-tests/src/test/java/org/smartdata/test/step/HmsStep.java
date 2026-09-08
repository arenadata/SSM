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
package org.smartdata.test.step;

import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.service.ConfigModifierService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;

import static java.lang.String.format;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.util.constant.CommonConstants.AGENT_CONF_NAME;
import static org.smartdata.test.util.constant.CommonConstants.MASTER_CONF_NAME;

@Slf4j
@Service
public class HmsStep {
  @Autowired
  private HiveSyncProgressDaoImpl hiveSyncProgressDao;
  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private ContainerManager containerManager;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private ApiStep apiStep;
  @Autowired
  private TableStep tableStep;
  @Autowired
  private ConfigModifierService configModifierService;

  @Step("Restore environment before HMS test")
  public HmsStep restoreEnv(boolean startSmmAfterRestore) throws IOException {
    apiStep.deleteAllRules();
    containerManager.stop(SSM_SERVER);
    configModifierService.restoreOriginalFile(MASTER_CONF_NAME);
    configModifierService.restoreOriginalFile(AGENT_CONF_NAME);
    dataBaseStep.dropHiveServersTablesExceptDefault()
        .truncateSsmHiveNotificationLogTable();
    hiveMetastoreEventDao.deleteAll();
    hiveSyncProgressDao.deleteAll();
    if (startSmmAfterRestore) {
      containerManager.start(SSM_SERVER);
    }
    return this;
  }

  @Step("Check successful sync actions for entity '{entityName}' has size {expectedSize}")
  public HmsStep checkSuccessSyncActions(int expectedSize, String entityName) {
    tableStep.checkTableRowsCountIs(expectedSize)
        .checkAllColumnCellsContain(expectedSize, ACTION, format("-entityName %s", entityName))
        .checkAllColumnCellsTextEqual(expectedSize, STATUS, SUCCESSFUL.getText());
    return this;
  }
}
