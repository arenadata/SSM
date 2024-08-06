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
package org.smartdata.metastore.dao;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.CmdletSearchRequest;
import org.springframework.dao.EmptyResultDataAccessException;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TestCmdletDao
    extends TestSearchableDao<CmdletSearchRequest, CmdletInfo, CmdletSortField, Long> {

  private static final long FIRST_CMDLET_ID = 0;
  private static final long SECOND_CMDLET_ID = 1;
  private static final long THIRD_CMDLET_ID = 2;

  private CmdletDao cmdletDao;

  @Before
  public void initCmdletDao() {
    cmdletDao = daoProvider.cmdletDao();
  }

  @Test
  public void testInsertGetCmdlet() {
    CmdletInfo cmdlet1 = new CmdletInfo(0, 1,
        CmdletState.EXECUTING, "test", 123123333L, 232444444L);
    CmdletInfo cmdlet2 = new CmdletInfo(1, 78,
        CmdletState.PAUSED, "tt", 123178333L, 232444994L);
    cmdletDao.insert(cmdlet1, cmdlet2);
    List<CmdletInfo> cmdlets = cmdletDao.search(CmdletSearchRequest.noFilters());
    assertEquals(2, cmdlets.size());
  }

  @Test
  public void testUpdateCmdlet() {
    CmdletInfo cmdlet1 = new CmdletInfo(0, 1,
        CmdletState.EXECUTING, "test", 123123333L, 232444444L);
    CmdletInfo cmdlet2 = new CmdletInfo(1, 78,
        CmdletState.PAUSED, "tt", 123178333L, 232444994L);
    cmdletDao.insert(cmdlet1, cmdlet2);
    cmdlet1.setState(CmdletState.DONE);
    cmdletDao.update(cmdlet1);
    CmdletInfo dbcmdlet1 = cmdletDao.getById(cmdlet1.getId());
    assertEquals(dbcmdlet1, cmdlet1);
    try {
      cmdletDao.getById(2000L);
    } catch (EmptyResultDataAccessException e) {
      Assert.assertTrue(true);
    }
  }

  @Test
  public void testDeleteACmdlet() {
    CmdletInfo cmdlet1 = new CmdletInfo(0, 1,
        CmdletState.EXECUTING, "test", 123123333L, 232444444L);
    CmdletInfo cmdlet2 = new CmdletInfo(1, 78,
        CmdletState.PAUSED, "tt", 123178333L, 232444994L);
    cmdletDao.insert(cmdlet1, cmdlet2);
    cmdletDao.delete(1);
    List<CmdletInfo> cmdlets = cmdletDao.search(CmdletSearchRequest.noFilters());
    assertEquals(1, cmdlets.size());
  }

  @Test
  public void testMaxId() {
    CmdletInfo cmdlet1 = new CmdletInfo(0, 1,
        CmdletState.EXECUTING, "test", 123123333L, 232444444L);
    CmdletInfo cmdlet2 = new CmdletInfo(1, 78,
        CmdletState.PAUSED, "tt", 123178333L, 232444994L);
    assertEquals(0, cmdletDao.getMaxId());
    cmdletDao.insert(cmdlet1, cmdlet2);
    assertEquals(2, cmdletDao.getMaxId());
  }

  @Test
  public void testSearchAllCmdlets() {
    insertCmdletsForSearch();

    testSearch(CmdletSearchRequest.noFilters(),
        FIRST_CMDLET_ID, SECOND_CMDLET_ID, THIRD_CMDLET_ID);
  }

  @Test
  public void testSearchById() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .id(FIRST_CMDLET_ID)
        .id(SECOND_CMDLET_ID)
        .build();
    testSearch(searchRequest,
        FIRST_CMDLET_ID, SECOND_CMDLET_ID);

    searchRequest = CmdletSearchRequest
        .builder()
        .id(THIRD_CMDLET_ID)
        .id(707L)
        .build();
    testSearch(searchRequest, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder().id(777L).build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByCmdletText() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest =
        CmdletSearchRequest.builder().textRepresentationLike("action").build();
    testSearch(searchRequest, FIRST_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest =
        CmdletSearchRequest.builder().textRepresentationLike("writ").build();
    testSearch(searchRequest, SECOND_CMDLET_ID);

    searchRequest =
        CmdletSearchRequest.builder().textRepresentationLike("unknown").build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchBySubmissionTime() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .submissionTime(new TimeInterval(Instant.ofEpochMilli(1), Instant.now()))
        .build();
    testSearch(searchRequest, FIRST_CMDLET_ID, SECOND_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .submissionTime(
            new TimeInterval(Instant.ofEpochMilli(2), Instant.ofEpochMilli(9)))
        .build();
    testSearch(searchRequest, SECOND_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .submissionTime(new TimeInterval(Instant.now(), Instant.now().plusSeconds(1)))
        .build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByRuleId() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .ruleId(1L)
        .ruleId(2L)
        .build();
    testSearch(searchRequest,
        FIRST_CMDLET_ID, SECOND_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .ruleId(1L)
        .ruleId(999L)
        .build();
    testSearch(searchRequest, FIRST_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder().ruleId(777L).build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByState() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .state(CmdletState.DISABLED)
        .state(CmdletState.PAUSED)
        .state(CmdletState.EXECUTING)
        .build();

    testSearch(searchRequest,
        FIRST_CMDLET_ID, SECOND_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .state(CmdletState.EXECUTING)
        .state(CmdletState.CANCELLED)
        .build();
    testSearch(searchRequest, SECOND_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .state(CmdletState.DONE)
        .build();
    testSearch(searchRequest);
  }

  @Test
  public void testSearchByStateChangedTime() {
    insertCmdletsForSearch();

    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .stateChangedTime(new TimeInterval(Instant.ofEpochMilli(10), Instant.now()))
        .build();
    testSearch(searchRequest, FIRST_CMDLET_ID, SECOND_CMDLET_ID, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .stateChangedTime(
            new TimeInterval(Instant.ofEpochMilli(11), Instant.ofEpochMilli(12)))
        .build();
    testSearch(searchRequest, THIRD_CMDLET_ID);

    searchRequest = CmdletSearchRequest.builder()
        .stateChangedTime(new TimeInterval(Instant.now(), Instant.now().plusSeconds(1)))
        .build();
    testSearch(searchRequest);
  }

  @Override
  protected Searchable<CmdletSearchRequest, CmdletInfo, CmdletSortField> searchable() {
    return cmdletDao;
  }

  @Override
  protected Long getIdentifier(CmdletInfo cmdletInfo) {
    return cmdletInfo.getId();
  }

  @Override
  protected CmdletSortField defaultSortField() {
    return CmdletSortField.ID;
  }

  private void insertCmdletsForSearch() {
    CmdletInfo cmdlet1 = CmdletInfo.builder()
        .setId(FIRST_CMDLET_ID)
        .setRuleId(1)
        .setActionIds(Arrays.asList(1L, 2L, 3L))
        .setState(CmdletState.DISABLED)
        .setParameters("action -key val1")
        .setGenerateTime(1L)
        .setStateChangedTime(10L)
        .build();

    CmdletInfo cmdlet2 = CmdletInfo.builder()
        .setId(SECOND_CMDLET_ID)
        .setRuleId(2)
        .setActionIds(Collections.singletonList(4L))
        .setState(CmdletState.EXECUTING)
        .setParameters("write -file test.txt")
        .setGenerateTime(2L)
        .setStateChangedTime(14L)
        .build();

    CmdletInfo cmdlet3 = CmdletInfo.builder()
        .setId(THIRD_CMDLET_ID)
        .setRuleId(1)
        .setActionIds(Collections.singletonList(5L))
        .setState(CmdletState.DISABLED)
        .setParameters("action -key another_val")
        .setGenerateTime(10L)
        .setStateChangedTime(11L)
        .build();

    cmdletDao.insert(cmdlet1, cmdlet2, cmdlet3);
  }
}
