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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.composite.HiveDiffSourceState;
import org.smartdata.hive.fetch.composite.NewHiveSourceStateRecord;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.INTERMEDIATE_EVENTS_STARTED;
import static org.smartdata.hive.fetch.composite.HiveDiffSourceState.SNAPSHOT_STARTED;

@Slf4j
public class CompositeHmsEventHandler implements HmsEventHandler {
  private final PlatformTransactionManager transactionManager;
  private final HmsBufferingEventHandler intermediateEventsResolver;
  private final HmsEventHandler delegate;

  private RecordsHandler recordsHandler;

  @lombok.Builder
  public CompositeHmsEventHandler(
      PlatformTransactionManager transactionManager,
      HmsBufferingEventHandler intermediateEventsResolver,
      HmsEventHandler delegate) {
    this.transactionManager = transactionManager;
    this.intermediateEventsResolver = intermediateEventsResolver;
    this.delegate = delegate;
    this.recordsHandler = new InitialRecordsHandler();
  }

  @Override
  public void handle(HmsEventStreamRecord record) throws Exception {
    try {
      handleAction(record);
    } catch (Exception e) {
      recordsHandler.fail();
      throw e;
    }
  }

  private void handleAction(HmsEventStreamRecord record) throws Exception {
    if (record instanceof NewHiveSourceStateRecord) {
      HiveDiffSourceState newState = ((NewHiveSourceStateRecord) record).getNewState();
      recordsHandler = recordsHandler.nextHandler(newState);
      return;
    }

    recordsHandler.handle(record);
  }

  interface RecordsHandler {
    void handle(HmsEventStreamRecord record) throws Exception;

    RecordsHandler nextHandler(HiveDiffSourceState newState) throws Exception;

    default void fail() {
      // do nothing
    }
  }

  class InitialRecordsHandler implements RecordsHandler {
    @Override
    public void handle(HmsEventStreamRecord record) {
      // do nothing
    }

    @Override
    public RecordsHandler nextHandler(HiveDiffSourceState newState) {
      if (newState == SNAPSHOT_STARTED) {
        return new SnapshotRecordsHandler();
      }

      if (newState == EVENTS_STARTED) {
        return new MetastoreEventsHandler();
      }

      throw new IllegalStateException("Unexpected state: " + newState);
    }
  }

  @RequiredArgsConstructor
  class SnapshotRecordsHandler implements RecordsHandler {
    private TransactionStatus transactionStatus;

    @Override
    public void handle(HmsEventStreamRecord record) throws Exception {
      if (transactionStatus == null) {
        transactionStatus = transactionManager.getTransaction(
            new DefaultTransactionDefinition());
      }
      delegate.handle(record);
    }

    @Override
    public RecordsHandler nextHandler(HiveDiffSourceState newState) {
      if (newState == INTERMEDIATE_EVENTS_STARTED) {
        return new IntermediateEventsHandler(transactionStatus);
      }

      if (newState == EVENTS_STARTED) {
        transactionManager.commit(transactionStatus);
        return new MetastoreEventsHandler();
      }

      return this;
    }

    @Override
    public void fail() {
      transactionManager.rollback(transactionStatus);
    }
  }

  @RequiredArgsConstructor
  class IntermediateEventsHandler implements RecordsHandler {
    private final TransactionStatus transactionStatus;

    @Override
    public void handle(HmsEventStreamRecord record) throws Exception {
      intermediateEventsResolver.handle(record);
    }

    @Override
    public RecordsHandler nextHandler(HiveDiffSourceState newState) {
      if (newState == EVENTS_STARTED) {
        intermediateEventsResolver.flush();
        transactionManager.commit(transactionStatus);
        return new MetastoreEventsHandler();
      }

      return this;
    }

    @Override
    public void fail() {
      transactionManager.rollback(transactionStatus);
    }
  }

  class MetastoreEventsHandler implements RecordsHandler {
    @Override
    public void handle(HmsEventStreamRecord record) throws Exception {
      delegate.handle(record);
    }

    @Override
    public RecordsHandler nextHandler(HiveDiffSourceState newState) {
      return this;
    }
  }
}
