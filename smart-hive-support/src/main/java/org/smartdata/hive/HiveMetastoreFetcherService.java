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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.smartdata.AbstractService;
import org.smartdata.SmartContext;
import org.smartdata.hdfs.impersonation.DisabledUserImpersonationStrategy;
import org.smartdata.hive.client.CachingMetaStoreClientProvider;
import org.smartdata.hive.client.MetaStoreClientProvider;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.fetch.composite.CompositeHmsEventSource;
import org.smartdata.hive.fetch.enrich.HmsEventEnricher;
import org.smartdata.hive.fetch.enrich.HmsFkRelatedResourcesSetter;
import org.smartdata.hive.fetch.enrich.HmsFunctionNameSetter;
import org.smartdata.hive.fetch.filter.CompositeHmsEventFilter;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.handler.AsyncHmsEventStreamHandler;
import org.smartdata.hive.handler.CompositeHmsEventHandler;
import org.smartdata.hive.handler.DbHmsEventHandler;
import org.smartdata.hive.handler.HmsEventHandler;
import org.smartdata.hive.handler.HmsEventStreamHandler;
import org.smartdata.hive.handler.HmsIntermediateEventsResolver;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;
import org.smartdata.hive.snapshot.HmsSnapshotEventSource;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.ResourceMapperRetryPolicy;
import org.smartdata.retry.RetryPolicyFactory;
import org.smartdata.retry.RetrySupport;
import org.springframework.transaction.PlatformTransactionManager;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;

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
      scheduledExecutorService = Executors.newScheduledThreadPool(8);

      HiveNotificationEventFactory eventFactory = new HiveNotificationEventFactory(
          GzipJSONMessageEncoder.getInstance()
      );
      resourceSource = buildEventSource(buildClientSupplier(), eventFactory);
      eventStreamHandler = buildStreamHandler(eventFactory);
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

  private HmsEventStreamHandler buildStreamHandler(
      HiveNotificationEventFactory eventFactory) {
    RetrySupport handlerRetrySupport = buildHandlerRetrySupport();

    return new AsyncHmsEventStreamHandler(
        buildCompositeEventHandler(handlerRetrySupport, eventFactory),
        new DbHmsEventHandler(unprocessedHiveEventDao, handlerRetrySupport),
        scheduledExecutorService
    );
  }

  private HmsEventHandler buildCompositeEventHandler(
      RetrySupport retrySupport, HiveNotificationEventFactory eventFactory) {
    DbHmsEventHandler delegate = new DbHmsEventHandler(hiveEventDao, retrySupport);

    return new CompositeHmsEventHandler(
        transactionManager,
        new HmsIntermediateEventsResolver(hiveEventDao, eventFactory),
        delegate
    );
  }

  private HmsEventSource buildEventSource(
      Supplier<IMetaStoreClient> metaStoreClientSupplier,
      HiveNotificationEventFactory eventFactory) {
    HmsEventFilter eventFilter = CompositeHmsEventFilter.fromConf(hiveSmartConf);

    return new CompositeHmsEventSource(
        metaStoreClientSupplier,
        buildSnapshotEventSource(metaStoreClientSupplier, eventFilter, eventFactory),
        buildInFlightEventSource(metaStoreClientSupplier, eventFilter),
        scheduledExecutorService,
        hiveSmartConf.getFetchBatchSize()
    );
  }

  private HmsSnapshotEventSource buildSnapshotEventSource(
      Supplier<IMetaStoreClient> metaStoreClientSupplier,
      HmsEventFilter eventFilter,
      HiveNotificationEventFactory eventFactory) {
    ExecutorService executorService = Executors.newFixedThreadPool(
        hiveSmartConf.getSnapshotFetcherThreadsCount());
    return new HmsSnapshotEventSource(
        metaStoreClientSupplier,
        executorService,
        eventFilter,
        eventFactory,
        hiveSmartConf
    );
  }

  private Supplier<IMetaStoreClient> buildClientSupplier() {
    Configuration metastoreConf = MetastoreConf.newMetastoreConf(hiveSmartConf);
    String metastoreUrl = MetastoreConf.getVar(metastoreConf, MetastoreConf.ConfVars.THRIFT_URIS);

    if (StringUtils.isBlank(metastoreUrl)) {
      throw new IllegalArgumentException("Metastore URL is not provided");
    }

    MetaStoreClientProvider metaStoreClientProvider = new CachingMetaStoreClientProvider(
        hiveSmartConf,
        new DisabledUserImpersonationStrategy()
    );
    return () -> metaStoreClientProvider.provide(metastoreUrl, null);
  }

  private HmsInFlightEventSource buildInFlightEventSource(
      Supplier<IMetaStoreClient> metaStoreClientSupplier,
      HmsEventFilter eventFilter) {
    MessageEncoder messageEncoder = GzipJSONMessageEncoder.getInstance();
    List<HmsEventEnricher> eventEnrichers = Arrays.asList(
        new HmsFunctionNameSetter(messageEncoder),
        new HmsFkRelatedResourcesSetter(messageEncoder)
    );

    return HmsInFlightEventSource.builder()
        .metaStoreClientSupplier(metaStoreClientSupplier)
        .executor(scheduledExecutorService)
        .eventFilter(eventFilter)
        .fetchPeriodMs(hiveSmartConf.getFetchPeriodMs())
        .eventBatchSize(hiveSmartConf.getFetchBatchSize())
        .eventEnrichers(eventEnrichers)
        .build();
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
}
