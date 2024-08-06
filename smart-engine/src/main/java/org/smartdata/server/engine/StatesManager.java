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
package org.smartdata.server.engine;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.AbstractService;
import org.smartdata.conf.Reconfigurable;
import org.smartdata.conf.ReconfigurableRegistry;
import org.smartdata.conf.ReconfigureException;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.accesscount.AccessCountTableManager;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.metrics.FileAccessEventSource;
import org.smartdata.metrics.impl.MetricsFactory;
import org.smartdata.model.PathChecker;
import org.smartdata.server.engine.data.AccessEventFetcher;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Polls metrics and events from NameNode.
 */
public class StatesManager extends AbstractService implements Reconfigurable {
  private final ServerContext serverContext;

  private ScheduledExecutorService executorService;
  private AccessCountTableManager accessCountTableManager;
  private AccessEventFetcher accessEventFetcher;
  private FileAccessEventSource fileAccessEventSource;
  @Getter
  private CachedFilesManager cachedFilesManager;
  private AbstractService statesUpdaterService;
  private PathChecker pathChecker;
  private volatile boolean working = false;

  public static final Logger LOG = LoggerFactory.getLogger(StatesManager.class);

  public StatesManager(ServerContext context) {
    super(context);
    this.serverContext = context;
  }

  /**
   * Load configure/data to initialize.
   */
  @Override
  public void init() throws IOException {
    LOG.info("Initializing ...");
    this.executorService = Executors.newScheduledThreadPool(4);
    this.accessCountTableManager = new AccessCountTableManager(
        serverContext.getMetaStore(), executorService, serverContext.getConf());
    this.fileAccessEventSource = MetricsFactory.createAccessEventSource(serverContext.getConf());
    this.accessEventFetcher = new AccessEventFetcher(
        serverContext.getConf(),
        accessCountTableManager.getAccessEventAggregator(),
        executorService,
        fileAccessEventSource.getCollector());
    this.pathChecker = new PathChecker(serverContext.getConf());
    this.cachedFilesManager =
        new CachedFilesManager(serverContext.getMetaStore().cacheFileDao());

    initStatesUpdaterService();
    if (statesUpdaterService == null) {
      ReconfigurableRegistry.registReconfigurableProperty(
          getReconfigurableProperties(), this);
    }

    LOG.info("Initialized.");
  }

  @Override
  public boolean inSafeMode() {
    if (statesUpdaterService == null) {
      return true;
    }
    return statesUpdaterService.inSafeMode();
  }

  /**
   * Start daemon threads in StatesManager for function.
   */
  @Override
  public void start() throws IOException {
    LOG.info("Starting ...");
    accessEventFetcher.start();
    if (statesUpdaterService != null) {
      statesUpdaterService.start();
    }
    working = true;
    LOG.info("Started. ");
  }

  @Override
  public void stop() throws IOException {
    working = false;
    LOG.info("Stopping ...");

    if (accessEventFetcher != null) {
      accessEventFetcher.stop();
    }
    if (this.fileAccessEventSource != null) {
      fileAccessEventSource.close();
    }
    if (statesUpdaterService != null) {
      statesUpdaterService.stop();
    }
    if (executorService != null) {
      executorService.shutdownNow();
    }

    LOG.info("Stopped.");
  }

  public List<AccessCountTable> getTablesForLast(long timeInMills) throws MetaStoreException {
    return accessCountTableManager.getTablesForLast(timeInMills);
  }

  public void reportFileAccessEvent(FileAccessEvent event) {
    String path = event.getPath();
    path = path + (path.endsWith("/") ? "" : "/");

    if (pathChecker.isIgnored(path)) {
      LOG.debug("Path {} is in the ignore list. Skip report file access event.", path);
      return;
    }

    if (!pathChecker.isCovered(path)) {
      LOG.debug("Path {} is not in the whitelist. Report file access event failed.", path);
      return;
    }
    event.setTimeStamp(System.currentTimeMillis());
    this.fileAccessEventSource.insertEventFromSmartClient(event);
  }

  public void reconfigureProperty(String property, String newVal)
      throws ReconfigureException {
    LOG.debug("Received reconfig event: property={} newVal={}",
        property, newVal);
    if (SmartConfKeys.SMART_DFS_NAMENODE_RPCSERVER_KEY.equals(property)) {
      if (statesUpdaterService != null) {
        throw new ReconfigureException(
            "States update service already been initialized.");
      }

      if (working) {
        initStatesUpdaterService();
      }
    }
  }

  public List<String> getReconfigurableProperties() {
    return Collections.singletonList(
        SmartConfKeys.SMART_DFS_NAMENODE_RPCSERVER_KEY);
  }

  private synchronized void initStatesUpdaterService() {
    try {
      try {
        statesUpdaterService = AbstractServiceFactory
            .createStatesUpdaterService(serverContext, serverContext.getMetaStore());
        statesUpdaterService.init();
      } catch (IOException e) {
        statesUpdaterService = null;
        LOG.warn("================================================================");
        LOG.warn("  Failed to create states updater service for: " + e.getMessage());
        LOG.warn("  This may leads to rule/action execution error. The reason why SSM "
            + "does not exit under this condition is some other feature depends on this.");
        LOG.warn("================================================================");
      }

      if (working) {
        try {
          statesUpdaterService.start();
        } catch (IOException e) {
          LOG.error("Failed to start states updater service.", e);
          statesUpdaterService = null;
        }
      }
    } catch (Throwable t) {
      LOG.info("", t);
    }
  }

  public AccessCountTableManager getAccessCountTableManager() {
    return accessCountTableManager;
  }
}
