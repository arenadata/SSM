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
import org.apache.hadoop.hive.metastore.HiveMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.smartdata.AbstractService;
import org.smartdata.SmartContext;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsInFlightEventSource;
import org.smartdata.hive.handler.AsyncHmsEventStreamHandler;
import org.smartdata.hive.handler.DbHmsEventHandler;
import org.smartdata.hive.handler.HmsEventStreamHandler;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.ResourceMapperRetryPolicy;
import org.smartdata.retry.RetryPolicyFactory;
import org.smartdata.retry.RetrySupport;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_MAX_RETRIES;
import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_MAX_RETRIES_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_RETRY_INTERVAL_MS;
import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_RETRY_INTERVAL_MS_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_RETRY_STRATEGY;
import static org.smartdata.hive.config.ConfigurationKeys.EVENT_APPLIER_RETRY_STRATEGY_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FETCH_BATCH_SIZE;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FETCH_BATCH_SIZE_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FETCH_PERIOD_MS;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FETCH_PERIOD_MS_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FULL_SYNC;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_FULL_SYNC_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_MAX_RETRIES;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_MAX_RETRIES_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_RETRY_INTERVAL_MS;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_RETRY_INTERVAL_MS_DEFAULT;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_RETRY_STRATEGY;
import static org.smartdata.hive.config.ConfigurationKeys.HMS_RETRY_STRATEGY_DEFAULT;

@Slf4j
public class HiveMetastoreFetcherService extends AbstractService {
  private final HmsEventDao hiveEventDao;
  private final HmsEventDao unprocessedHiveEventDao;

  private HmsEventSource resourceSource;
  private HmsEventStreamHandler eventStreamHandler;
  private ScheduledExecutorService scheduledExecutorService;

  public HiveMetastoreFetcherService(
      SmartContext context,
      HmsEventDao hiveEventDao,
      HmsEventDao unprocessedHiveEventDao
  ) {
    super(context);
    this.hiveEventDao = hiveEventDao;
    this.unprocessedHiveEventDao = unprocessedHiveEventDao;
  }

  @Override
  public void init() throws IOException {
    try {
      scheduledExecutorService = Executors.newScheduledThreadPool(5);

      HiveMetaStoreClient hiveMetaStoreClient = new HiveMetaStoreClient(getContext().getConf());

      resourceSource = buildResourceSource(hiveMetaStoreClient, buildFetcherRetrySupport());
      eventStreamHandler = buildStreamHandler();
    } catch (MetaException metaException) {
      throw new IOException("Error initializing Hive Metastore client", metaException);
    }
  }

  @Override
  public void start() {
    Optional<Long> latestEventId = hiveEventDao.getLatestExternalEventId();

    HmsEventStream eventStream;

    boolean fullSync = getConf().getBoolean(HMS_FULL_SYNC, HMS_FULL_SYNC_DEFAULT);
    if (fullSync) {
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
        new DbHmsEventHandler(hiveEventDao, handlerRetrySupport),
        new DbHmsEventHandler(unprocessedHiveEventDao, handlerRetrySupport),
        scheduledExecutorService
    );
  }

  private HmsEventSource buildResourceSource(
      HiveMetaStoreClient hiveMetaStoreClient,
      RetrySupport retrySupport
  ) {
    long fetchPeriod = getConf().getLong(
        HMS_FETCH_PERIOD_MS,
        HMS_FETCH_PERIOD_MS_DEFAULT);

    int batchSize = getConf().getInt(
        HMS_FETCH_BATCH_SIZE,
        HMS_FETCH_BATCH_SIZE_DEFAULT);

    return new HmsInFlightEventSource(
        hiveMetaStoreClient,
        scheduledExecutorService,
        retrySupport,
        fetchPeriod,
        batchSize,
        null
    );
  }

  private RetrySupport buildFetcherRetrySupport() {
    RetryPolicyFactory retryPolicyFactory = new RetryPolicyFactory();

    ResourceMapperRetryPolicy retryPolicy = retryPolicyFactory.provide(
        getConf().getEnum(HMS_RETRY_STRATEGY, HMS_RETRY_STRATEGY_DEFAULT),
        getConf().getInt(HMS_MAX_RETRIES, HMS_MAX_RETRIES_DEFAULT),
        getConf().getLong(HMS_RETRY_INTERVAL_MS, HMS_RETRY_INTERVAL_MS_DEFAULT)
    );
    return new PolicyBasedRetrySupport(retryPolicy, Thread::sleep);
  }

  private RetrySupport buildHandlerRetrySupport() {
    RetryPolicyFactory retryPolicyFactory = new RetryPolicyFactory();

    ResourceMapperRetryPolicy retryPolicy = retryPolicyFactory.provide(
        getConf().getEnum(EVENT_APPLIER_RETRY_STRATEGY, EVENT_APPLIER_RETRY_STRATEGY_DEFAULT),
        getConf().getInt(EVENT_APPLIER_MAX_RETRIES, EVENT_APPLIER_MAX_RETRIES_DEFAULT),
        getConf().getLong(EVENT_APPLIER_RETRY_INTERVAL_MS, EVENT_APPLIER_RETRY_INTERVAL_MS_DEFAULT)
    );
    return new PolicyBasedRetrySupport(retryPolicy, Thread::sleep);
  }
}
