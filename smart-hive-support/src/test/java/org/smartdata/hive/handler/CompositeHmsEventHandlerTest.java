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

package org.smartdata.hive.handler;

import lombok.Data;
import lombok.Getter;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.RetryException;
import org.smartdata.retry.RetryPolicyFactory;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.INTERMEDIATE_EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.SNAPSHOT_STARTED;
import static org.smartdata.hive.fetch.composite.NewHiveSourceStateRecord.newStateRecord;

public class CompositeHmsEventHandlerTest {
  private MockTransactionManager transactionManager;
  private MockIntermediateEventResolver intermediateEventResolver;
  private MockResourceDiffCollector mockDiffCollectorDelegate;

  private CompositeHmsEventHandler eventHandler;

  @Before
  public void setUp() {
    transactionManager = new MockTransactionManager();
    intermediateEventResolver = new MockIntermediateEventResolver();
    mockDiffCollectorDelegate = new MockResourceDiffCollector();

    eventHandler = CompositeHmsEventHandler.builder()
        .delegate(mockDiffCollectorDelegate)
        .intermediateEventsResolver(intermediateEventResolver)
        .transactionManager(transactionManager)
        .retrySupport(new PolicyBasedRetrySupport(
            RetryPolicyFactory.NO_RETRIES_POLICY, Thread::sleep))
        .build();
  }

  @Test
  public void testHandleSnapshotRecordChainWithIntermediateEvents() throws Exception {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        newStateRecord(INTERMEDIATE_EVENTS_STARTED),
        new DummyRecord(4),
        new DummyRecord(5),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(6)
    );

    List<HmsEventStreamRecord> expectedIntermediateRecords = Arrays.asList(
        new DummyRecord(4),
        new DummyRecord(5)
    );

    List<HmsEventStreamRecord> expectedDelegateRecords = Arrays.asList(
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        new DummyRecord(6)
    );

    testHandleRecordChain(
        records,
        expectedIntermediateRecords,
        expectedDelegateRecords
    );
    assertEquals(1, transactionManager.isCommited.size());
  }

  @Test
  public void testHandleSnapshotRecordChainWithoutIntermediateEvents() throws Exception {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(6)
    );

    List<HmsEventStreamRecord> expectedDelegateRecords = Arrays.asList(
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        new DummyRecord(6)
    );

    testHandleRecordChain(
        records,
        Collections.emptyList(),
        expectedDelegateRecords
    );
    assertEquals(1, transactionManager.isCommited.size());
  }

  @Test
  public void testHandleStreamingRecordChainWithoutIntermediateEvents() throws Exception {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(1),
        new DummyRecord(22),
        new DummyRecord(3333),
        new DummyRecord(6)
    );

    List<HmsEventStreamRecord> expectedDelegateRecords = Arrays.asList(
        new DummyRecord(1),
        new DummyRecord(22),
        new DummyRecord(3333),
        new DummyRecord(6)
    );

    testHandleRecordChain(
        records,
        Collections.emptyList(),
        expectedDelegateRecords
    );
  }

  @Test
  public void testRollbackTxIfSnapshotHandlerFails() {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new FailingRecord()
    );

    checkTxRollback(records);
  }

  @Test
  public void testRollbackTxIfIntermediateEventResolverFails() {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        new DummyRecord(3),
        newStateRecord(INTERMEDIATE_EVENTS_STARTED),
        new DummyRecord(4),
        new DummyRecord(5),
        new FailingRecord()
    );

    checkTxRollback(records);
  }

  private void checkTxRollback(List<HmsEventStreamRecord> records) {
    assertThrows(RetryException.class, () -> {
      for (HmsEventStreamRecord record : records) {
        eventHandler.handle(record);
      }
    });

    assertTrue(transactionManager.isCommited.isEmpty());
    assertEquals(1, transactionManager.isRollbacked.size());
  }

  private void testHandleRecordChain(List<HmsEventStreamRecord> records,
      List<HmsEventStreamRecord> expectedIntermediateRecords,
      List<HmsEventStreamRecord> expectedDelegateRecords) throws Exception {
    for (HmsEventStreamRecord record : records) {
      eventHandler.handle(record);
    }

    assertEquals(expectedIntermediateRecords, intermediateEventResolver.getHandledRecords());
    assertEquals(expectedDelegateRecords, mockDiffCollectorDelegate.getHandledRecords());
    assertTrue(transactionManager.isRollbacked.isEmpty());
  }

  private static class MockResourceDiffCollector implements HmsEventHandler {
    @Getter
    private final List<HmsEventStreamRecord> handledRecords = new ArrayList<>();

    @Override
    public void handle(HmsEventStreamRecord record) {
      if (record instanceof FailingRecord) {
        throw new IllegalArgumentException("FailingRecord");
      }

      handledRecords.add(record);
    }
  }

  private static class MockIntermediateEventResolver extends MockResourceDiffCollector
      implements HmsBufferingEventHandler {
    @Override
    public void flush() {

    }
  }

  private static class MockTransactionManager implements PlatformTransactionManager {
    private final Map<TransactionStatus, Boolean> isCommited = new HashMap<>();
    private final Map<TransactionStatus, Boolean> isRollbacked = new HashMap<>();

    @Override
    public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
      return new SimpleTransactionStatus();
    }

    @Override
    public void commit(TransactionStatus status) throws TransactionException {
      isCommited.put(status, true);
    }

    @Override
    public void rollback(TransactionStatus status) throws TransactionException {
      isRollbacked.put(status, true);
    }
  }

  @Data
  private static class DummyRecord implements HmsEventStreamRecord {
    private final int id;
  }

  @Data
  private static class FailingRecord implements HmsEventStreamRecord {
    // no content
  }
}