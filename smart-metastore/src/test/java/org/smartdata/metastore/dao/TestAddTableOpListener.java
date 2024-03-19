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
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.smartdata.metastore.MetaStore;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

import static org.mockito.Mockito.when;
import static org.smartdata.metastore.TestDBUtil.addAccessCountTableToDeque;

public class TestAddTableOpListener {

  @Mock
  private MetaStore adapter;

  private final ExecutorService executorService = Executors.newFixedThreadPool(4);

  private final ReentrantLock accessCountLock = new ReentrantLock();

  private AccessCountTableAggregator aggregator;

  @Before
  public void setup() {
    MockitoAnnotations.initMocks(this);
    aggregator = new AccessCountTableAggregator(adapter);
    when(adapter.getAccessCountLock()).thenReturn(accessCountLock);
  }

  @Test
  public void testMinuteTableListener() throws Exception {
    long oneSec = 1000L;
    TableEvictor tableEvictor = new CountEvictor(adapter, 10);
    AccessCountTableDeque minuteTableDeque = new AccessCountTableDeque(tableEvictor);
    TableAddOpListener minuteTableListener =
        TableAddOpListener.perMinute(minuteTableDeque, aggregator, executorService);
    AccessCountTableDeque secondTableDeque =
        new AccessCountTableDeque(tableEvictor, minuteTableListener);

    AccessCountTable table1 =
        new AccessCountTable(45 * oneSec, 50 * oneSec);
    AccessCountTable table2 =
        new AccessCountTable(50 * oneSec, 55 * oneSec);
    AccessCountTable table3 =
        new AccessCountTable(55 * oneSec, 60 * oneSec);

    addAccessCountTableToDeque(secondTableDeque, table1);
    Assert.assertTrue(minuteTableDeque.isEmpty());

    addAccessCountTableToDeque(secondTableDeque, table2);
    Assert.assertTrue(minuteTableDeque.isEmpty());

    addAccessCountTableToDeque(secondTableDeque, table3);
    Assert.assertEquals(1, minuteTableDeque.size());

    AccessCountTable expected = new AccessCountTable(0L, 60 * oneSec);
    Assert.assertEquals(minuteTableDeque.poll(), expected);
  }

  @Test
  public void testHourTableListener() throws Exception {
    long oneMin = 60 * 1000L;
    TableEvictor tableEvictor = new CountEvictor(adapter, 10);
    AccessCountTableDeque hourTableDeque = new AccessCountTableDeque(tableEvictor);
    TableAddOpListener hourTableListener =
        TableAddOpListener.perHour(hourTableDeque, aggregator, executorService);
    AccessCountTableDeque minuteTableDeque =
        new AccessCountTableDeque(tableEvictor, hourTableListener);

    AccessCountTable table1 =
        new AccessCountTable(57 * oneMin, 58 * oneMin);
    AccessCountTable table2 =
        new AccessCountTable(58 * oneMin, 59 * oneMin);
    AccessCountTable table3 =
        new AccessCountTable(59 * oneMin, 60 * oneMin);

    addAccessCountTableToDeque(minuteTableDeque, table1);
    Assert.assertTrue(hourTableDeque.isEmpty());

    addAccessCountTableToDeque(minuteTableDeque, table2);
    Assert.assertTrue(hourTableDeque.isEmpty());

    addAccessCountTableToDeque(minuteTableDeque, table3);
    Assert.assertEquals(1, hourTableDeque.size());

    AccessCountTable expected = new AccessCountTable(0L, 60 * oneMin);
    Assert.assertEquals(hourTableDeque.poll(), expected);
  }

  @Test
  public void testDayTableListener() throws Exception {
    long oneHour = 60 * 60 * 1000L;
    TableEvictor tableEvictor = new CountEvictor(adapter, 10);
    AccessCountTableDeque dayTableDeque = new AccessCountTableDeque(tableEvictor);
    TableAddOpListener dayTableListener =
        TableAddOpListener.perDay(dayTableDeque, aggregator, executorService);
    AccessCountTableDeque hourTableDeque =
        new AccessCountTableDeque(tableEvictor, dayTableListener);

    AccessCountTable table1 =
        new AccessCountTable(21 * oneHour, 22 * oneHour);
    AccessCountTable table2 =
        new AccessCountTable(22 * oneHour, 23 * oneHour);
    AccessCountTable table3 =
        new AccessCountTable(23 * oneHour, 24 * oneHour);

    addAccessCountTableToDeque(hourTableDeque, table1);
    Assert.assertTrue(dayTableDeque.isEmpty());

    addAccessCountTableToDeque(hourTableDeque, table2);
    Assert.assertTrue(dayTableDeque.isEmpty());

    addAccessCountTableToDeque(hourTableDeque, table3);
    Assert.assertEquals(1, dayTableDeque.size());

    AccessCountTable today = new AccessCountTable(0L, 24 * oneHour);
    Assert.assertEquals(dayTableDeque.poll(), today);
  }
}
