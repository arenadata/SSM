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
package org.smartdata.hive.catalog;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.handler.HmsEventHandler;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.List;

/**
 * Fills the Hive catalog by replaying the HMS events, which are already stored in SSM,
 * e.g. if the catalog wasn't filled before the SSM upgrade. The stored events are
 * the ones replicated by the HMS sync rules, so the catalog is consistent
 * with the replicated metadata.
 *
 * <p>The catalog and its state are updated in a single transaction,
 * so the previous catalog state is kept if the replay fails.
 */
@Slf4j
public class HiveCatalogEventsReplayer {
  private final HmsEventDao eventDao;
  private final HmsEventHandler catalogHandler;
  private final HiveCatalogDao catalogDao;
  private final HiveCatalogStateDao catalogStateDao;
  private final PlatformTransactionManager transactionManager;
  private final int batchSize;

  @lombok.Builder
  public HiveCatalogEventsReplayer(
      HmsEventDao eventDao,
      HmsEventHandler catalogHandler,
      HiveCatalogDao catalogDao,
      HiveCatalogStateDao catalogStateDao,
      PlatformTransactionManager transactionManager,
      int batchSize) {
    this.eventDao = eventDao;
    this.catalogHandler = catalogHandler;
    this.catalogDao = catalogDao;
    this.catalogStateDao = catalogStateDao;
    this.transactionManager = transactionManager;
    this.batchSize = batchSize;
  }

  public void replay() throws Exception {
    TransactionStatus transaction = transactionManager.getTransaction(
        new DefaultTransactionDefinition());
    try {
      replayAction();
      transactionManager.commit(transaction);
    } catch (Exception e) {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
      throw e;
    }
  }

  private void replayAction() throws Exception {
    catalogDao.deleteAll();

    long lastEventId = 0L;
    long replayedEventsCount = 0L;

    List<HiveNotificationEvent> events;
    do {
      events = eventDao.getEventsAfter(lastEventId, batchSize);
      for (HiveNotificationEvent event : events) {
        catalogHandler.handle(event);
        lastEventId = event.getId();
      }

      replayedEventsCount += events.size();
      log.debug("Replayed {} HMS events to the Hive catalog", replayedEventsCount);
      // the incomplete batch is the last one
    } while (events.size() == batchSize);

    catalogStateDao.markInitialized();
    log.info("Replayed {} HMS events to the Hive catalog", replayedEventsCount);
  }
}
