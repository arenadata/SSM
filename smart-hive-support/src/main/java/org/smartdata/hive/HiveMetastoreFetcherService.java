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
package org.smartdata.hive;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.HiveMetaStoreClient;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.smartdata.AbstractService;
import org.smartdata.SmartContext;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.fetch.composite.CompositeHmsEventSource;
import org.smartdata.hive.handler.AsyncHmsEventStreamHandler;
import org.smartdata.hive.handler.CompositeHmsEventHandler;
import org.smartdata.hive.handler.DbHmsEventHandler;
import org.smartdata.hive.handler.HmsBufferingEventHandler;
import org.smartdata.hive.handler.HmsEventHandler;
import org.smartdata.hive.handler.HmsEventStreamHandler;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;
import org.smartdata.hive.snapshot.HmsSnapshotEventSource;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.ResourceMapperRetryPolicy;
import org.smartdata.retry.RetryPolicyFactory;
import org.smartdata.retry.RetrySupport;
import org.springframework.transaction.PlatformTransactionManager;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.smartdata.hdfs.HadoopUtil.doAsCurrentUser;

@Slf4j
public class HiveMetastoreFetcherService extends AbstractService {
  private final HiveSmartConf hiveSmartConf;
  private final HmsEventDao hiveEventDao;
  private final HmsEventDao unprocessedHiveEventDao;
  private final PlatformTransactionManager transactionManager;

  private HmsEventSource resourceSource;
  private HmsEventStreamHandler eventStreamHandler;
  private ScheduledExecutorService scheduledExecutorService;

  public HiveMetastoreFetcherService(
      SmartContext context,
      HmsEventDao hiveEventDao,
      HmsEventDao unprocessedHiveEventDao,
      PlatformTransactionManager transactionManager
  ) {
    super(context);
    this.hiveSmartConf = new HiveSmartConf(context.getConf());
    this.hiveEventDao = hiveEventDao;
    this.unprocessedHiveEventDao = unprocessedHiveEventDao;
    this.transactionManager = transactionManager;
  }

  @Override
  public void init() throws IOException {
    try {
      scheduledExecutorService = Executors.newScheduledThreadPool(16);

      resourceSource = buildEventSource(
          buildMetastoreClient(),
          buildFetcherRetrySupport());
      eventStreamHandler = buildStreamHandler();
    } catch (Exception metaException) {
      throw new IOException("Error initializing Hive Metastore client", metaException);
    }
  }

  @Override
  public void start() {
    Optional<Long> latestEventId = hiveEventDao.getLatestExternalEventId();

    HmsEventStream eventStream;

    if (hiveSmartConf.isFullMetastoreSync()) {
      log.info("Running full resync of resource diffs");
      // if the full resync is required, then restart fetcher from scratch
      hiveEventDao.deleteAll();
      eventStream = resourceSource.eventStream();
    } else if (latestEventId.isPresent()) {
      log.info("Start fetching resource diffs from id {}", latestEventId.get());
      // start from the last valid handled diff id
      eventStream = resourceSource.eventStreamFrom(latestEventId.get());
    } else {
      log.info("No last handled resource diff id is found. " +
          "Fetching resource diffs from scratch");
      // if there is no already handled diff id
      // and no restart is required, then start from scratch
      eventStream = resourceSource.eventStream();
    }

    eventStreamHandler.collectAsync(eventStream);
  }

  @Override
  public void stop() throws IOException {
    scheduledExecutorService.shutdown();
    resourceSource.close();
  }

  private HmsEventStreamHandler buildStreamHandler() {
    RetrySupport handlerRetrySupport = buildHandlerRetrySupport();

    return new AsyncHmsEventStreamHandler(
        buildCompositeEventHandler(handlerRetrySupport),
        new DbHmsEventHandler(unprocessedHiveEventDao, handlerRetrySupport),
        scheduledExecutorService
    );
  }

  private HmsEventHandler buildCompositeEventHandler(RetrySupport retrySupport) {
    DbHmsEventHandler delegate = new DbHmsEventHandler(hiveEventDao, retrySupport);

    return new CompositeHmsEventHandler(
        retrySupport,
        transactionManager,
        // todo: replace with proper snapshot to event transition handler
        new DelegatingBufferingEventHandler(delegate),
        delegate
    );
  }

  private HmsEventSource buildEventSource(
      IMetaStoreClient hiveMetaStoreClient,
      RetrySupport retrySupport
  ) {
    return new CompositeHmsEventSource(
        hiveMetaStoreClient,
        buildSnapshotEventSource(hiveMetaStoreClient, retrySupport),
        buildInFlightEventSource(hiveMetaStoreClient, retrySupport),
        scheduledExecutorService,
        hiveSmartConf.getFetchBatchSize()
    );
  }

  private HmsSnapshotEventSource buildSnapshotEventSource(
      IMetaStoreClient hiveMetaStoreClient,
      RetrySupport retrySupport
  ) {
    return new HmsSnapshotEventSource(
        hiveMetaStoreClient,
        scheduledExecutorService,
        retrySupport,
        new HiveNotificationEventFactory(
            GzipJSONMessageEncoder.getInstance()
        ),
        hiveSmartConf
    );
  }

  private HmsInFlightEventSource buildInFlightEventSource(
      IMetaStoreClient hiveMetaStoreClient,
      RetrySupport retrySupport
  ) {
    return new HmsInFlightEventSource(
        hiveMetaStoreClient,
        scheduledExecutorService,
        retrySupport,
        hiveSmartConf.getFetchPeriodMs(),
        hiveSmartConf.getFetchBatchSize(),
        null
    );
  }

  private RetrySupport buildFetcherRetrySupport() {
    RetryPolicyFactory retryPolicyFactory = new RetryPolicyFactory();

    ResourceMapperRetryPolicy retryPolicy = retryPolicyFactory.provide(
        hiveSmartConf.getHiveListenerRetryStrategy(),
        hiveSmartConf.getHiveListenerMaxRetries(),
        hiveSmartConf.getHiveListenerRetryIntervalMs()
    );
    return new PolicyBasedRetrySupport(retryPolicy, Thread::sleep);
  }

  private RetrySupport buildHandlerRetrySupport() {
    RetryPolicyFactory retryPolicyFactory = new RetryPolicyFactory();

    ResourceMapperRetryPolicy retryPolicy = retryPolicyFactory.provide(
        hiveSmartConf.getEventApplierRetryStrategy(),
        hiveSmartConf.getEventApplierMaxRetries(),
        hiveSmartConf.getEventApplierRetryIntervalMs()
    );
    return new PolicyBasedRetrySupport(retryPolicy, Thread::sleep);
  }

  private IMetaStoreClient buildMetastoreClient() {
    try {
      return doAsCurrentUser(this::buildMetastoreClientAction);
    } catch (IOException e) {
      log.error("Failed to build metastore client", e);
      throw new RuntimeException(e);
    }
  }

  private IMetaStoreClient buildMetastoreClientAction() throws MetaException {
    return new HiveMetaStoreClient(hiveSmartConf);
  }

  // todo: remove when we add proper snapshot to event transition
  @RequiredArgsConstructor
  private static class DelegatingBufferingEventHandler implements HmsBufferingEventHandler {
    private final HmsEventHandler delegate;

    @Override
    public void flush() {
      // do nothing
    }

    @Override
    public void handle(HmsEventStreamRecord record) throws Exception {
      delegate.handle(record);
    }
  }
}
