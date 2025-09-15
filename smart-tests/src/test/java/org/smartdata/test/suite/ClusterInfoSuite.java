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
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.step.ClusterInfoStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.HottestFilesStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.PaginationStep;
import org.smartdata.test.step.TableStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;

import static java.lang.String.format;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.EXECUTORS;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.ID;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.REGISTER_TIME;
import static org.smartdata.test.element.TableElement.TableType.SECONDARY;
import static org.smartdata.test.model.SortOrder.ASC;


@Feature("Cluster info page")
public class ClusterInfoSuite extends SsmBaseSuite {

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  private DataBaseStep dataBaseStep;

  @Autowired
  private ClusterInfoStep clusterInfoStep;

  @Autowired
  private HottestFilesStep hottestFilesStep;

  @Autowired
  private PaginationStep paginationStep;

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
    clusterInfoStep.checkClusterInfoRegisterTimeFiltration();
  }

  @TmsLink("91460")
  @Story("Cluster info. Hottest files")
  @Test(description = "Check 'Hottest files' sorting")
  public void testHottestFilesSorting() {
    prepareDataForHottestFilesTest();
    hottestFilesStep.checkSorting();
  }

  @TmsLink("91459")
  @Story("Cluster info. Hottest files")
  @Test(description = "Check 'Hottest files' filtration")
  public void testHottestFilesFiltration() {
    prepareDataForHottestFilesTest();
    hottestFilesStep.checkFilePathFiltration();
  }

  @TmsLink("91458")
  @Story("Cluster info. Hottest files")
  @Test(description = "Check 'Hottest files' pagination")
  public void testHottestFilesPagination() {
    List<String> filePathList = prepareDataForHottestFilesPaginationTest();
    hottestFilesStep.checkPagination(filePathList);
  }

  @Step("Create fake hottest files rows")
  private void prepareDataForHottestFilesTest() {
    dataBaseStep.insertFakeDataForHottestFilesTest();
    tableStep.refreshPage();
    tableStep.checkTableRowsCountIs(SECONDARY, 2);
  }

  @Step("Create hottest files rows for pagination test")
  private List<String> prepareDataForHottestFilesPaginationTest() {
    List<String> filePathList = new ArrayList<>();
    int filesQuantity = 101;
    for (int i = 0; i < filesQuantity; i++) {
      String filePath = format("test%s.txt", i);
      dataBaseStep.insertDataForHottestFilesPaginationTest(filePath);
      filePathList.add(filePath);
    }
    clusterInfoStep.refreshPage();
    return filePathList;
  }
}
