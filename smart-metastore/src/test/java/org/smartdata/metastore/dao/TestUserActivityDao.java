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

import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.AuditSortField;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.audit.UserActivityEvent;
import org.smartdata.model.request.AuditSearchRequest;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.smartdata.model.audit.UserActivityObject.CMDLET;
import static org.smartdata.model.audit.UserActivityObject.RULE;
import static org.smartdata.model.audit.UserActivityOperation.CREATE;
import static org.smartdata.model.audit.UserActivityOperation.DELETE;
import static org.smartdata.model.audit.UserActivityOperation.START;
import static org.smartdata.model.audit.UserActivityOperation.STOP;
import static org.smartdata.model.audit.UserActivityResult.FAILURE;
import static org.smartdata.model.audit.UserActivityResult.SUCCESS;

public class TestUserActivityDao
    extends TestSearchableDao<AuditSearchRequest, UserActivityEvent, AuditSortField, Instant> {
  private static final Instant FIRST_EVENT_TIMESTAMP =
      Instant.EPOCH.plus(10, ChronoUnit.MINUTES);
  private static final Instant SECOND_EVENT_TIMESTAMP =
      Instant.EPOCH.plus(15, ChronoUnit.MINUTES);
  private static final Instant THIRD_EVENT_TIMESTAMP =
      Instant.EPOCH.plus(20, ChronoUnit.MINUTES);

  private UserActivityDao userActivityDao;

  @Before
  public void initUserActivityDao() {
    userActivityDao = daoProvider.userActivityDao();
    insertTestEvents();
  }

  @Test
  public void testEmptyFiltersSearch() throws Exception {
    List<UserActivityEvent> events =
        userActivityDao.search(AuditSearchRequest.empty());

    assertEquals(3, events.size());
  }

  @Test
  public void testFetchAllColumns() throws Exception {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .objectIds(Collections.singletonList(1L))
        .build();

    UserActivityEvent expectedEvent = UserActivityEvent.builder()
        .id(3L)
        .username("anonymous")
        .timestamp(THIRD_EVENT_TIMESTAMP)
        .objectId(1L)
        .objectType(CMDLET)
        .operation(CREATE)
        .result(SUCCESS)
        .build();

    List<UserActivityEvent> events = userActivityDao.search(searchRequest);

    assertEquals(1, events.size());
    assertEquals(expectedEvent, events.get(0));
  }

  @Test
  public void testEmptyFiltersSearchWithPagination() throws Exception {
    PageRequest<AuditSortField> pageRequest = PageRequest.<AuditSortField>builder()
        .offset(0L)
        .limit(2)
        .sortByAsc(AuditSortField.OBJECT_ID)
        .sortByDesc(AuditSortField.TIMESTAMP)
        .build();

    SearchResult<UserActivityEvent> searchResult =
        userActivityDao.search(AuditSearchRequest.empty(), pageRequest);

    List<UserActivityEvent> items = searchResult.getItems();
    assertEquals(3L, searchResult.getTotal());
    assertEquals(2L, items.size());

    assertEquals(THIRD_EVENT_TIMESTAMP, items.get(0).getTimestamp());
    assertEquals(SECOND_EVENT_TIMESTAMP, items.get(1).getTimestamp());
  }

  @Test
  public void testSearchByUser() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .userLike("use")
        .build();

    testSearch(searchRequest, FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .userLike("anonymous")
        .build();

    testSearch(searchRequest, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .userLike("unknown")
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByObjectIds() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .objectIds(Arrays.asList(1L, 32L))
        .build();

    testSearch(searchRequest, FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .objectIds(Collections.singletonList(32L))
        .build();

    testSearch(searchRequest, FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .objectIds(Collections.singletonList(777L))
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByObjectTypes() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .objectTypes(Arrays.asList(RULE, CMDLET))
        .build();

    testSearch(searchRequest,
        FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .objectTypes(Collections.singletonList(CMDLET))
        .build();

    testSearch(searchRequest, THIRD_EVENT_TIMESTAMP);
  }

  @Test
  public void testSearchByResult() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .results(Arrays.asList(SUCCESS, FAILURE))
        .build();

    testSearch(searchRequest,
        FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .results(Collections.singletonList(SUCCESS))
        .build();

    testSearch(searchRequest, FIRST_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);
  }

  @Test
  public void testSearchByOperations() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .operations(Arrays.asList(START, STOP))
        .build();

    testSearch(searchRequest, FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .operations(Collections.singletonList(CREATE))
        .build();

    testSearch(searchRequest, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .operations(Collections.singletonList(DELETE))
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testSearchByTimestamp() {
    AuditSearchRequest searchRequest = AuditSearchRequest.builder()
        .timestampBetween(new TimeInterval(Instant.EPOCH, Instant.now()))
        .build();

    testSearch(searchRequest,
        FIRST_EVENT_TIMESTAMP, SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .timestampBetween(
            new TimeInterval(SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP))
        .build();

    testSearch(searchRequest, SECOND_EVENT_TIMESTAMP, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .timestampBetween(
            new TimeInterval(SECOND_EVENT_TIMESTAMP.plusSeconds(1), null))
        .build();

    testSearch(searchRequest, THIRD_EVENT_TIMESTAMP);

    searchRequest = AuditSearchRequest.builder()
        .timestampBetween(
            new TimeInterval(null, FIRST_EVENT_TIMESTAMP.minusSeconds(1)))
        .build();

    testSearch(searchRequest);
  }

  @Override
  protected Searchable<AuditSearchRequest, UserActivityEvent, AuditSortField> searchable() {
    return userActivityDao;
  }

  @Override
  protected Instant getIdentifier(UserActivityEvent userActivityEvent) {
    return userActivityEvent.getTimestamp();
  }

  @Override
  protected AuditSortField defaultSortField() {
    return AuditSortField.TIMESTAMP;
  }

  private void insertTestEvents() {
    UserActivityEvent ruleStartEvent = UserActivityEvent.builder()
        .username("user")
        .timestamp(FIRST_EVENT_TIMESTAMP)
        .objectId(32L)
        .objectType(RULE)
        .operation(START)
        .result(SUCCESS)
        .build();

    userActivityDao.insert(ruleStartEvent);

    UserActivityEvent ruleStopEvent = UserActivityEvent.builder()
        .username("user")
        .timestamp(SECOND_EVENT_TIMESTAMP)
        .objectId(32L)
        .objectType(RULE)
        .operation(STOP)
        .result(FAILURE)
        .additionalInfo("rule with wrong syntax")
        .build();

    userActivityDao.insert(ruleStopEvent);

    UserActivityEvent cmdletSubmitEvent = UserActivityEvent.builder()
        .username("anonymous")
        .timestamp(THIRD_EVENT_TIMESTAMP)
        .objectId(1L)
        .objectType(CMDLET)
        .operation(CREATE)
        .result(SUCCESS)
        .build();

    userActivityDao.insert(cmdletSubmitEvent);
  }
}
