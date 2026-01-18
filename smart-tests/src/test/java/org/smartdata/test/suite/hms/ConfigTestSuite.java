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
import io.qameta.allure.TmsLink;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.step.ClusterInfoStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.EXECUTORS;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.ID;
import static org.smartdata.test.element.TableElement.getRowByCellValue;
import static org.smartdata.test.model.SsmComponent.HADOOP_DATANODE;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.util.constant.CommonConstants.DATANODE_HOST_NAME;
import static org.smartdata.test.util.constant.CommonConstants.SSM_SERVER_HOST_NAME;

@Feature("Configuration changes during tests")
public class ConfigTestSuite extends SsmBaseSuite {

  @Autowired
  private ConfigModifierService configModifierService;

  @Autowired
  private ContainerManager containerManager;

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  private ClusterInfoStep clusterInfoStep;

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

  @TmsLink("91462")
  @Story("Configuration. Cmdlet executors")
  @Test(description = "Test changing master cmdlet executors from 9 to 5 and verify UI reflects change")
  public void testMasterCmdletExecutorsChange() throws Exception {
    // Given: Default executors is 9
    tableStep.checkRowColumnValue(getRowByCellValue(ID, SSM_SERVER_HOST_NAME), EXECUTORS, "8");

    // When: Change to 5 executors and restart server
    configModifierService.setProperty("smart-site-master.xml", "smart.cmdlet.executors", "5");
    containerManager.restart(SSM_SERVER);

    // Then: UI should show 5 executors
    clusterInfoStep.refreshPage();
    loginStep.loginAs(UserRole.OWNER);
    tableStep.checkRowColumnValue(getRowByCellValue(ID, SSM_SERVER_HOST_NAME), EXECUTORS, "5");
  }

  @TmsLink("91463")
  @Story("Configuration. Cmdlet executors")
  @Test(description = "Test changing agent cmdlet executors from 8 to 4 and verify UI reflects change")
  public void testAgentCmdletExecutorsChange() throws Exception {
    // Given: Default executors is 8
    tableStep.checkRowColumnValue(getRowByCellValue(ID, DATANODE_HOST_NAME), EXECUTORS, "8");

    // When: Change to 4 executors and restart agent
    configModifierService.setProperty("smart-site-agent.xml", "smart.cmdlet.executors", "4");
    containerManager.restart(HADOOP_DATANODE);

    // Then: UI should show 4 executors
    clusterInfoStep.refreshPage();
    tableStep.checkRowColumnValue(getRowByCellValue(ID, DATANODE_HOST_NAME), EXECUTORS, "4");
  }

//    @TmsLink("91464")
//    @Story("Configuration. Multiple properties")
//    @Test(description = "Test changing multiple properties simultaneously and verify UI")
//    public void testMultipleConfigChanges() throws Exception {
//        // Given: Default values
//        tableStep.checkRowColumnValue(getRowByCellValue(ID, SSM_SERVER_HOST_NAME), EXECUTORS, "9");
//        tableStep.checkRowColumnValue(getRowByCellValue(ID, DATANODE_HOST_NAME), EXECUTORS, "8");
//
//        // When: Change both master and agent executors
//        configModifierService.setProperty("smart-site-master.xml", "smart.cmdlet.executors", "3");
//        configModifierService.setProperty("smart-site-agent.xml", "smart.cmdlet.executors", "2");
//
//        // Restart both services
//        dockerService.restartContainer("ssm-server");
//        dockerService.restartContainer("hadoop-datanode");
//
//        // Then: UI should reflect both changes
//        clusterInfoStep.refreshPage();
//        tableStep.checkRowColumnValue(getRowByCellValue(ID, SSM_SERVER_HOST_NAME), EXECUTORS, "3");
//        tableStep.checkRowColumnValue(getRowByCellValue(ID, DATANODE_HOST_NAME), EXECUTORS, "2");
//    }
//
//    @TmsLink("91465")
//    @Story("Configuration. Property restoration")
//    @Test(description = "Test that configurations are properly restored after test execution")
//    public void testConfigRestoration() throws Exception {
//        // Given: Change a property
//        configModifierService.setProperty("smart-site-master.xml", "smart.cmdlet.executors", "1");
//        dockerService.restartContainer("ssm-server");
//        clusterInfoStep.refreshPage();
//        tableStep.checkRowColumnValue(getRowByCellValue(ID, SSM_SERVER_HOST_NAME), EXECUTORS, "1");
//
//        // When: Test completes (AfterMethod will restore)
//
//        // Then: Config should be restored automatically
//        // This is verified by the @AfterMethod running after the test
//    }
}
