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
import static org.smartdata.hive.handler.HmsEventHandlerChain.bufferingHandlerChain;
import static org.smartdata.hive.handler.HmsEventHandlerChain.handlerChain;

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
  public void testChainedHandlersReceiveRecordsInAllPhases() throws Exception {
    MockResourceDiffCollector additionalHandler = new MockResourceDiffCollector();
    eventHandler = CompositeHmsEventHandler.builder()
        .transactionManager(transactionManager)
        .intermediateEventsResolver(bufferingHandlerChain(intermediateEventResolver, additionalHandler))
        .delegate(handlerChain(additionalHandler, mockDiffCollectorDelegate))
        .build();

    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        new DummyRecord(2),
        newStateRecord(INTERMEDIATE_EVENTS_STARTED),
        new DummyRecord(3),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(4)
    );

    testHandleRecordChain(
        records,
        Collections.singletonList(new DummyRecord(3)),
        Arrays.asList(new DummyRecord(1), new DummyRecord(2), new DummyRecord(4))
    );

    assertEquals(
        Arrays.asList(new DummyRecord(1), new DummyRecord(2), new DummyRecord(3), new DummyRecord(4)),
        additionalHandler.getHandledRecords());
    assertEquals(1, intermediateEventResolver.getFlushCount());
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

  @Test
  public void testCleanPreviousStateInSnapshotTx() throws Exception {
    List<String> actions = new ArrayList<>();
    eventHandler = CompositeHmsEventHandler.builder()
        .transactionManager(transactionManager)
        .intermediateEventsResolver(intermediateEventResolver)
        .delegate(record -> actions.add("handle " + record))
        .snapshotStateCleaner(() -> actions.add(
            "clean, active tx count: " + transactionManager.activeTransactionsCount()))
        .build();

    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(2)
    );
    for (HmsEventStreamRecord record : records) {
      eventHandler.handle(record);
    }

    List<String> expectedActions = Arrays.asList(
        "clean, active tx count: 1",
        "handle " + new DummyRecord(1),
        "handle " + new DummyRecord(2)
    );
    assertEquals(expectedActions, actions);
    assertEquals(1, transactionManager.isCommited.size());
    assertTrue(transactionManager.isRollbacked.isEmpty());
  }

  @Test
  public void testNotCleanPreviousStateWithoutSnapshot() throws Exception {
    List<String> actions = new ArrayList<>();
    eventHandler = CompositeHmsEventHandler.builder()
        .transactionManager(transactionManager)
        .intermediateEventsResolver(intermediateEventResolver)
        .delegate(mockDiffCollectorDelegate)
        .snapshotStateCleaner(() -> actions.add("clean"))
        .build();

    testHandleRecordChain(
        Arrays.asList(newStateRecord(EVENTS_STARTED), new DummyRecord(1)),
        Collections.emptyList(),
        Collections.singletonList(new DummyRecord(1))
    );
    assertTrue(actions.isEmpty());
  }

  @Test
  public void testRollbackTxIfSnapshotStateCleanerFails() {
    eventHandler = CompositeHmsEventHandler.builder()
        .transactionManager(transactionManager)
        .intermediateEventsResolver(intermediateEventResolver)
        .delegate(mockDiffCollectorDelegate)
        .snapshotStateCleaner(() -> {
          throw new IllegalArgumentException("Cleaner failure");
        })
        .build();

    checkTxRollback(Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1)
    ));
    assertTrue(mockDiffCollectorDelegate.getHandledRecords().isEmpty());
  }

  @Test
  public void testRollbackTxOnEndOfStreamDuringSnapshot() throws Exception {
    checkTxRollbackOnEndOfStream(Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        HmsEventStreamRecord.endOfStreamRecord()
    ));
  }

  @Test
  public void testRollbackTxOnEndOfStreamDuringIntermediateEvents() throws Exception {
    checkTxRollbackOnEndOfStream(Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        newStateRecord(INTERMEDIATE_EVENTS_STARTED),
        new DummyRecord(2),
        HmsEventStreamRecord.endOfStreamRecord()
    ));
  }

  @Test
  public void testKeepCommittedSnapshotOnEndOfStreamDuringEvents() throws Exception {
    List<HmsEventStreamRecord> records = Arrays.asList(
        newStateRecord(SNAPSHOT_STARTED),
        new DummyRecord(1),
        newStateRecord(EVENTS_STARTED),
        new DummyRecord(2),
        HmsEventStreamRecord.endOfStreamRecord()
    );
    for (HmsEventStreamRecord record : records) {
      eventHandler.handle(record);
    }

    assertEquals(Arrays.asList(new DummyRecord(1), new DummyRecord(2)),
        mockDiffCollectorDelegate.getHandledRecords());
    assertEquals(1, transactionManager.isCommited.size());
    assertTrue(transactionManager.isRollbacked.isEmpty());
  }

  private void checkTxRollbackOnEndOfStream(List<HmsEventStreamRecord> records) throws Exception {
    for (HmsEventStreamRecord record : records) {
      eventHandler.handle(record);
    }

    assertTrue(transactionManager.isCommited.isEmpty());
    assertEquals(1, transactionManager.isRollbacked.size());
    // the end of the stream isn't passed to the handlers
    assertTrue(mockDiffCollectorDelegate.getHandledRecords().stream()
        .noneMatch(HmsEventStreamRecord::isLastRecord));
  }

  private void checkTxRollback(List<HmsEventStreamRecord> records) {
    assertThrows(IllegalArgumentException.class, () -> {
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
    @Getter
    private int flushCount = 0;

    @Override
    public void flush() {
      flushCount++;
    }
  }

  private static class MockTransactionManager implements PlatformTransactionManager {
    private final Map<TransactionStatus, Boolean> isCommited = new HashMap<>();
    private final Map<TransactionStatus, Boolean> isRollbacked = new HashMap<>();
    private int transactionsCount = 0;

    @Override
    public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
      transactionsCount++;
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

    private long activeTransactionsCount() {
      return transactionsCount - isCommited.size() - isRollbacked.size();
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