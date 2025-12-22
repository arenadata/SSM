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
package org.smartdata.server.engine.file;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.AbstractService;
import org.smartdata.metastore.accesscount.DbAccessEventAggregator;
import org.smartdata.metastore.accesscount.DbFileAccessCountManager;
import org.smartdata.metastore.accesscount.FileAccessCountManager;
import org.smartdata.metastore.accesscount.failover.AccessCountFailoverFactory;
import org.smartdata.metastore.partition.FileAccessPartitionManagerImpl;
import org.smartdata.metastore.partition.FileAccessPartitionService;
import org.smartdata.metastore.partition.cleanup.FileAccessPartitionRetentionPolicyExecutorFactory;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.metrics.FileAccessEventSource;
import org.smartdata.metrics.impl.FileAccessMetricsFactory;
import org.smartdata.model.PathChecker;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.data.AccessEventFetcher;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.smartdata.conf.SmartConfKeys.ACCESS_EVENT_SOURCE_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.ACCESS_EVENT_SOURCE_KEY;
import static org.smartdata.utils.PathUtil.addPathSeparator;
import static org.springframework.transaction.annotation.Isolation.SERIALIZABLE;

/**
 * Polls metrics and events from FS.
 */
@Slf4j
public class DbFileAccessManager extends AbstractService implements FileAccessManager {
  private final ServerContext serverContext;

  private ScheduledExecutorService executorService;
  @Getter
  private DbFileAccessCountManager fileAccessCountManager;
  private AccessEventFetcher accessEventFetcher;
  private FileAccessEventSource fileAccessEventSource;
  private FileAccessPartitionService fileAccessPartitionService;
  private PathChecker pathChecker;

  public DbFileAccessManager(ServerContext context) {
    super(context);
    this.serverContext = context;
  }

  /**
   * Load configure/data to initialize.
   */
  @Override
  public void init() throws IOException {
    log.info("Initializing ...");
    this.executorService = Executors.newScheduledThreadPool(5);

    TransactionRunner transactionRunner =
        new TransactionRunner(serverContext.getMetaStore().transactionManager());
    transactionRunner.setIsolationLevel(SERIALIZABLE);
    this.fileAccessCountManager = new DbFileAccessCountManager(
        transactionRunner,
        serverContext.getMetaStore().accessCountEventDao(),
        serverContext.getMetaStore().cacheFileDao());

    String accessEventSource = serverContext.getConf().get(
        ACCESS_EVENT_SOURCE_KEY,
        ACCESS_EVENT_SOURCE_DEFAULT);
    this.fileAccessEventSource = FileAccessMetricsFactory.createAccessEventSource(accessEventSource);

    AccessCountFailoverFactory accessCountFailoverFactory =
        new AccessCountFailoverFactory(serverContext.getConf());
    DbAccessEventAggregator accessEventAggregator = new DbAccessEventAggregator(
        serverContext.getMetaStore().generalFileInfoSource(),
        fileAccessCountManager,
        accessCountFailoverFactory.create());
    this.accessEventFetcher = new AccessEventFetcher(
        serverContext.getConf(),
        accessEventAggregator,
        executorService,
        fileAccessEventSource.getCollector(),
        serverContext.getMetricsFactory());
    this.pathChecker = new PathChecker(serverContext.getConf());

    FileAccessPartitionRetentionPolicyExecutorFactory retentionPolicyFactory =
        new FileAccessPartitionRetentionPolicyExecutorFactory(serverContext.getMetaStore());
    this.fileAccessPartitionService = new FileAccessPartitionService(
        executorService,
        new FileAccessPartitionManagerImpl(serverContext.getMetaStore()),
        retentionPolicyFactory.createPolicyExecutor(serverContext.getConf())
    );

    log.info("Initialized.");
  }

  @Override
  public void reportFileAccessEvent(FileAccessEvent event) {
    String path = addPathSeparator(event.getPath());

    if (pathChecker.isIgnored(path)) {
      log.debug("Path {} is in the ignore list. Skip report file access event.", path);
      return;
    }

    if (!pathChecker.isCovered(path)) {
      log.debug("Path {} is not in the whitelist. Report file access event failed.", path);
      return;
    }
    event.setTimestamp(System.currentTimeMillis());
    fileAccessEventSource.insertEventFromSmartClient(event);
  }

  @Override
  public FileAccessCountManager getFileAccessCountManager() {
    return fileAccessCountManager;
  }

  /**
   * Start daemon threads in StatesManager for function.
   */
  @Override
  public void start() throws IOException {
    log.info("Starting ...");
    fileAccessPartitionService.start();
    accessEventFetcher.start();

    log.info("Started. ");
  }

  @Override
  public void stop() throws IOException {
    log.info("Stopping ...");

    try {
      if (fileAccessPartitionService != null) {
        fileAccessPartitionService.stop();
      }
    } catch (Exception e) {
      log.error("Failed to stop FileAccessPartitionService", e);
    }

    try {
      if (accessEventFetcher != null) {
        accessEventFetcher.stop();
      }
    } catch (Exception e) {
      log.error("Failed to stop AccessEventFetcher", e);
    }

    try {
      if (this.fileAccessEventSource != null) {
        fileAccessEventSource.close();
      }
    } catch (Exception e) {
      log.error("Failed to close FileAccessEventSource", e);
    }

    try {
      if (executorService != null) {
        executorService.shutdownNow();
      }
    } catch (Exception e) {
      log.error("Failed to shutdown ExecutorService", e);
    }

    log.info("Stopped.");
  }
}
