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
package org.smartdata.test.suite;

import io.arenadata.test.model.UserRole;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.step.ClusterInfoStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.TableStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.EXECUTORS;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.ID;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.REGISTER_TIME;
import static org.smartdata.test.model.SortOrder.ASC;


@Feature("Cluster info page")
public class ClusterInfoSuite extends SsmBaseSuite {

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  ClusterInfoStep clusterInfoStep;

  @BeforeMethod
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
  }

  @TmsLink("91392")
  @Story("Cluster info. Hosts")
  @Test(description = "Check 'Hosts' sorting")
  public void testHostsSorting() {
    tableStep.checkSelectedSorting(ID, ASC)
        .checkColumnValuesIsSorted(ID, ASC)
        .checkSorting(EXECUTORS)
        .checkSorting(REGISTER_TIME)
        .checkSorting(ID);
  }

  @TmsLink("91393")
  @Story("Cluster info. Hosts")
  @Test(description = "Check 'Hosts' filtration")
  public void testHostsFiltration() {
    tableStep.checkTableRowsCountIs(2);
    clusterInfoStep.checkAuditDateFiltration();
  }
}
