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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.MetaStore;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.mockito.Mockito.mock;
import static org.smartdata.metastore.TestDBUtil.addAccessCountTableToDeque;
import static org.smartdata.metastore.utils.Constants.ONE_SECOND_IN_MILLIS;

public class TestTableEvictor {
  private MetaStore adapter;
  private AccessCountTableAggregator aggregator;

  private ExecutorService executorService;

  @Before
  public void setUp() {
    adapter = mock(MetaStore.class);
    aggregator = new AccessCountTableAggregator(adapter);
    executorService = Executors.newSingleThreadExecutor();
  }

  @After
  public void shutdown() {
    executorService.shutdown();
  }

  @Test
  public void testCountEvictor() {
    CountEvictor countEvictor = new CountEvictor(adapter, 2);
    AccessCountTableDeque tableDeque = new AccessCountTableDeque(countEvictor);

    tableDeque.add(new AccessCountTable(0L, 1L));
    countEvictor.evictTables(tableDeque, 0L);
    Assert.assertEquals(1, tableDeque.size());

    tableDeque.add(new AccessCountTable(1L, 2L));
    countEvictor.evictTables(tableDeque, 0L);
    Assert.assertEquals(2, tableDeque.size());

    tableDeque.add(new AccessCountTable(3L, 4L));
    countEvictor.evictTables(tableDeque, 0L);
    Assert.assertEquals(3, tableDeque.size());

    AccessCountTable firstExpectedTable = new AccessCountTable(4L, 59 * ONE_SECOND_IN_MILLIS);
    tableDeque.add(firstExpectedTable);
    countEvictor.evictTables(tableDeque, 0L);
    Assert.assertEquals(4, tableDeque.size());

    AccessCountTable secondExpectedTable = new AccessCountTable(
        59 * ONE_SECOND_IN_MILLIS, 60 * ONE_SECOND_IN_MILLIS);
    tableDeque.add(secondExpectedTable);
    countEvictor.evictTables(tableDeque, ONE_SECOND_IN_MILLIS);
    Assert.assertEquals(2, tableDeque.size());

    Assert.assertTrue(tableDeque.contains(firstExpectedTable));
    Assert.assertTrue(tableDeque.contains(secondExpectedTable));
  }

  @Test
  public void testDontEvictIfNotAggregatedYet() throws Exception {
    AccessCountTableDeque secondDeque = buildSecondDeque(1);

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(0L, 1L));
    Assert.assertEquals(1, secondDeque.size());

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(1L, 2L));
    Assert.assertEquals(2, secondDeque.size());

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(2L, 3L));
    Assert.assertEquals(3, secondDeque.size());

    AccessCountTable lastFirstMinuteTable = new AccessCountTable(
        59 * ONE_SECOND_IN_MILLIS, 60 * ONE_SECOND_IN_MILLIS);
    addAccessCountTableToDeque(secondDeque, lastFirstMinuteTable);

    Assert.assertEquals(1, secondDeque.size());
    Assert.assertTrue(secondDeque.contains(lastFirstMinuteTable));
  }

  @Test
  public void testDontEvictDuringAggregationIfThresholdNotMet() throws Exception {
    AccessCountTableDeque secondDeque = buildSecondDeque(10);

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(0L, 1L));
    Assert.assertEquals(1, secondDeque.size());

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(1L, 2L));
    Assert.assertEquals(2, secondDeque.size());

    addAccessCountTableToDeque(secondDeque, new AccessCountTable(2L, 3L));
    Assert.assertEquals(3, secondDeque.size());

    AccessCountTable lastFirstMinuteTable = new AccessCountTable(
        59 * ONE_SECOND_IN_MILLIS, 60 * ONE_SECOND_IN_MILLIS);
    addAccessCountTableToDeque(secondDeque, lastFirstMinuteTable);

    Assert.assertEquals(4, secondDeque.size());
  }

  private AccessCountTableDeque buildSecondDeque(int evictThreshold) {
    AccessCountTableDeque minuteDeque = new AccessCountTableDeque(
        new CountEvictor(adapter, 999));
    TableAddOpListener minuteTableListener =
        TableAddOpListener.perMinute(minuteDeque, aggregator, executorService);

    TableEvictor secondEvictor = new CountEvictor(adapter, evictThreshold);
    return new AccessCountTableDeque(secondEvictor, minuteTableListener);
  }
}
