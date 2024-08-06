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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.ActionSortField;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.ActionSource;
import org.smartdata.model.ActionState;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.ActionSearchRequest;
import org.springframework.dao.EmptyResultDataAccessException;
import org.testcontainers.shaded.com.google.common.collect.ImmutableMap;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestActionDao
    extends TestSearchableDao<ActionSearchRequest, ActionInfo, ActionSortField, Long> {

  private static final long FIRST_ACTION_ID = 0;
  private static final long SECOND_ACTION_ID = 1;
  private static final long THIRD_ACTION_ID = 2;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();
  private ActionDao actionDao;

  @Before
  public void initActionDao() {
    actionDao = daoProvider.actionDao();
  }

  @Test
  public void testInsertGetAction() {
    Map<String, String> args = new HashMap<>();
    ActionInfo actionInfo = new ActionInfo(1, 1,
        "cache", args, "Test",
        "Test", false, 123213213L, true, 123123L,
        100);
    actionDao.insert(new ActionInfo[] {actionInfo});
    ActionInfo dbActionInfo = actionDao.getById(1L);
    Assert.assertEquals(actionInfo, dbActionInfo);
    // Get wrong id
    expectedException.expect(EmptyResultDataAccessException.class);
    actionDao.getById(100L);
  }

  @Test
  public void testUpdateAction() {
    Map<String, String> args = new HashMap<>();
    ActionInfo actionInfo = new ActionInfo(1, 1,
        "cache", args, "Test",
        "Test", false, 123213213L, true, 123123L,
        100);
    actionDao.insert(actionInfo);
    actionInfo.setSuccessful(true);
    actionDao.update(actionInfo);
    ActionInfo dbActionInfo = actionDao.getById(actionInfo.getActionId());
    Assert.assertEquals(actionInfo, dbActionInfo);
  }

  @Test
  public void testGetNewDeleteAction() {
    Map<String, String> args = new HashMap<>();
    ActionInfo actionInfo = new ActionInfo(1, 1,
        "cache", args, "Test",
        "Test", false, 123213213L, true, 123123L,
        100);
    List<ActionInfo> actionInfoList = actionDao.getLatestActions(0);
    // Get from empty table
    Assert.assertTrue(actionInfoList.isEmpty());
    actionDao.insert(actionInfo);
    actionInfo.setActionId(2);
    actionDao.insert(actionInfo);
    actionInfoList = actionDao.getLatestActions(0);
    Assert.assertEquals(2, actionInfoList.size());
    actionInfoList = actionDao.getByIds(Arrays.asList(1L, 2L));
    Assert.assertEquals(2, actionInfoList.size());
    actionDao.delete(actionInfo.getActionId());
    actionInfoList = actionDao.search(ActionSearchRequest.noFilters());
    Assert.assertEquals(1, actionInfoList.size());
  }

  @Test
  public void testMaxId() {
    Map<String, String> args = new HashMap<>();
    ActionInfo actionInfo = new ActionInfo(1, 1,
        "cache", args, "Test",
        "Test", false, 123213213L, true, 123123L,
        100);
    Assert.assertEquals(0, actionDao.getMaxId());
    actionDao.insert(actionInfo);
    Assert.assertEquals(2, actionDao.getMaxId());
  }

  @Test
  public void testSearchAllActions() {
    insertActionsForSearch();

    testSearch(ActionSearchRequest.noFilters(),
        FIRST_ACTION_ID, SECOND_ACTION_ID, THIRD_ACTION_ID);
  }

  @Test
  public void testSearchById() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .id(FIRST_ACTION_ID)
        .id(THIRD_ACTION_ID)
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .id(SECOND_ACTION_ID)
        .build();

    testSearch(searchRequest, SECOND_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .id(777L)
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByTextRepresentation() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .textRepresentationLike("write -")
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, SECOND_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .textRepresentationLike("read -file test")
        .build();

    testSearch(searchRequest, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .textRepresentationLike("another text")
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchBySubmissionTime() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.EPOCH, Instant.now()))
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, SECOND_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.ofEpochMilli(1), Instant.ofEpochMilli(14)))
        .build();

    testSearch(searchRequest, SECOND_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .submissionTime(new TimeInterval(
            Instant.ofEpochMilli(16), Instant.now()))
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByHosts() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .host("localhost")
        .host("remote_host")
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, SECOND_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .host("remote_host")
        .build();

    testSearch(searchRequest, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .host("another_host")
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByStates() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .state(ActionState.RUNNING)
        .build();

    testSearch(searchRequest, SECOND_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .state(ActionState.FAILED)
        .build();

    testSearch(searchRequest, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .state(ActionState.SUCCESSFUL)
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .state(ActionState.RUNNING)
        .state(ActionState.SUCCESSFUL)
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, SECOND_ACTION_ID);
  }

  @Test
  public void testSearchBySources() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .source(ActionSource.USER)
        .source(ActionSource.RULE)
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, SECOND_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .source(ActionSource.USER)
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .source(ActionSource.RULE)
        .build();

    testSearch(searchRequest, SECOND_ACTION_ID);
  }

  @Test
  public void testSearchByCompletionTime() {
    insertActionsForSearch();

    ActionSearchRequest searchRequest = ActionSearchRequest.builder()
        .completionTime(new TimeInterval(
            Instant.ofEpochMilli(1), Instant.now()))
        .build();

    testSearch(searchRequest, FIRST_ACTION_ID, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .completionTime(new TimeInterval(
            Instant.ofEpochMilli(11), Instant.now()))
        .build();

    testSearch(searchRequest, THIRD_ACTION_ID);

    searchRequest = ActionSearchRequest.builder()
        .completionTime(new TimeInterval(
            Instant.ofEpochMilli(101), Instant.now()))
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSortByStatus() {
    insertActionsForSearch();

    PageRequest<ActionSortField> pageRequest = PageRequest.<ActionSortField>builder()
        .sortByAsc(ActionSortField.STATUS)
        .build();

    testPagedSearch(
        ActionSearchRequest.noFilters(),
        pageRequest,
        SECOND_ACTION_ID, THIRD_ACTION_ID, FIRST_ACTION_ID);
  }

  private void insertActionsForSearch() {
    ActionInfo actionInfo1 = ActionInfo.builder()
        .setActionId(FIRST_ACTION_ID)
        .setCmdletId(1)
        .setActionName("write")
        .setArgs(ImmutableMap.of("-file", "license.txt"))
        .setResult("success")
        .setLog("logloglog")
        .setSuccessful(true)
        .setCreateTime(0)
        .setFinished(true)
        .setFinishTime(10)
        .setExecHost("localhost")
        .build();

    ActionInfo actionInfo2 = ActionInfo.builder()
        .setActionId(SECOND_ACTION_ID)
        .setCmdletId(2)
        .setActionName("write")
        .setArgs(ImmutableMap.of("-arg", "check", "-ruleId", "1"))
        .setCreateTime(1)
        .setFinished(false)
        .setExecHost("localhost")
        .build();

    ActionInfo actionInfo3 = ActionInfo.builder()
        .setActionId(THIRD_ACTION_ID)
        .setCmdletId(1)
        .setActionName("read")
        .setArgs(ImmutableMap.of("-file", "test.txt"))
        .setSuccessful(false)
        .setCreateTime(15)
        .setFinished(true)
        .setFinishTime(100)
        .setExecHost("remote_host")
        .build();

    actionDao.insert(actionInfo1, actionInfo2, actionInfo3);
  }

  @Override
  protected Searchable<ActionSearchRequest, ActionInfo, ActionSortField> searchable() {
    return actionDao;
  }

  @Override
  protected Long getIdentifier(ActionInfo actionInfo) {
    return actionInfo.getActionId();
  }

  @Override
  protected ActionSortField defaultSortField() {
    return ActionSortField.ID;
  }
}
