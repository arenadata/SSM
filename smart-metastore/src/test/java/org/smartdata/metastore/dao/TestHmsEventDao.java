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
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.metastore.TestDaoBase;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestHmsEventDao extends TestDaoBase {
  private HmsEventDao eventDao;

  @Before
  public void initDao() {
    eventDao = daoProvider.hmsEventDao();
  }

  @Test
  public void testGetEventsAfterInStoringOrder() {
    for (long externalId : new long[]{5, 3, 7, 4}) {
      eventDao.insert(event(externalId));
    }

    List<HiveNotificationEvent> firstBatch = eventDao.getEventsAfter(0L, 3);
    assertEquals(Arrays.asList(5L, 3L, 7L), externalIds(firstBatch));

    long lastId = firstBatch.get(firstBatch.size() - 1).getId();
    List<HiveNotificationEvent> secondBatch = eventDao.getEventsAfter(lastId, 3);
    assertEquals(Collections.singletonList(4L), externalIds(secondBatch));

    long lastIdOfSecondBatch = secondBatch.get(0).getId();
    assertTrue(eventDao.getEventsAfter(lastIdOfSecondBatch, 3).isEmpty());
  }

  @Test
  public void testGetEventsAfterWithoutEvents() {
    assertTrue(eventDao.getEventsAfter(0L, 10).isEmpty());
  }

  private static List<Long> externalIds(List<HiveNotificationEvent> events) {
    return events.stream()
        .map(HiveNotificationEvent::getExternalId)
        .collect(Collectors.toList());
  }

  private static HiveNotificationEvent event(long externalId) {
    return HiveNotificationEvent.builder()
        .externalId(externalId)
        .eventTime(0L)
        .eventType("CREATE")
        .entityType("TABLE")
        .fullName("db.tbl" + externalId)
        .catalogName("hive")
        .dbName("db")
        .tableName("tbl" + externalId)
        .relatedResources(Collections.emptySet())
        .build();
  }
}
