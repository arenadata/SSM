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
package org.smartdata.server.engine.cmdlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.SmartService;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.server.engine.ServerContext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class InMemoryRegistry implements SmartService {
  private static final Logger LOG = LoggerFactory.getLogger(InMemoryRegistry.class);

  private final Map<Long, CmdletInfo> unfinishedCmdlets;
  private final Map<Long, ActionInfo> actions;
  private final Map<Long, CmdletInfo> cmdlets;
  private final List<Long> cmdletsToDelete;
  private final MetaStore metaStore;

  private final RuleCmdletTracker ruleCmdletTracker;

  private final int cmdletCacheSyncBatchSize;

  private final ScheduledExecutorService executorService;

  public InMemoryRegistry(
      ServerContext context,
      RuleCmdletTracker ruleCmdletTracker,
      ScheduledExecutorService executorService) {
    this.ruleCmdletTracker = ruleCmdletTracker;
    this.executorService = executorService;
    this.unfinishedCmdlets = new ConcurrentHashMap<>();
    this.actions = new ConcurrentHashMap<>();
    this.cmdlets = new ConcurrentHashMap<>();
    this.cmdletsToDelete = new ArrayList<>();

    this.metaStore = context.getMetaStore();
    this.cmdletCacheSyncBatchSize = context.getConf()
        .getInt(SmartConfKeys.SMART_CMDLET_CACHE_BATCH,
            SmartConfKeys.SMART_CMDLET_CACHE_BATCH_DEFAULT);
  }

  @Override
  public void init() throws IOException {
  }

  @Override
  public void start() throws IOException {
    executorService.scheduleAtFixedRate(this::syncWithMetastore, 200, 50,
        TimeUnit.MILLISECONDS);
  }

  @Override
  public void stop() throws IOException {
    executorService.shutdownNow();

    syncWithMetastore();
  }

  public CmdletInfo updateCmdlet(long cmdletId, Consumer<CmdletInfo> cmdletConsumer) {
    return unfinishedCmdlets.computeIfPresent(cmdletId, (key, cmdlet) -> {
      cmdletConsumer.accept(cmdlet);
      return cmdlet;
    });
  }

  public ActionInfo updateAction(long actionId, Consumer<ActionInfo> actionConsumer) {
    return actions.computeIfPresent(actionId, (key, action) -> {
      actionConsumer.accept(action);
      return action;
    });
  }

  public void addAction(ActionInfo actionInfo) {
    actions.put(actionInfo.getActionId(), actionInfo);
  }

  public void addUnfinishedCmdlet(CmdletInfo cmdletInfo) {
    unfinishedCmdlets.put(cmdletInfo.getId(), cmdletInfo);
  }

  public void addCmdlet(CmdletInfo cmdletInfo) {
    cmdlets.put(cmdletInfo.getId(), cmdletInfo);
  }

  public void deleteCmdletsAsync(List<Long> cmdletIds) {
    synchronized (cmdletsToDelete) {
      cmdletsToDelete.addAll(cmdletIds);
    }
  }

  public CmdletInfo getUnfinishedCmdlet(long cmdletId) {
    return unfinishedCmdlets.get(cmdletId);
  }

  public ActionInfo getUnfinishedAction(long actionId) {
    return actions.get(actionId);
  }

  public Map<Long, CmdletInfo> getUnfinishedCmdlets() {
    return unfinishedCmdlets;
  }

  public Map<Long, ActionInfo> getUnfinishedActions() {
    return actions;
  }

  private void syncWithMetastore() {
    if (cmdlets.isEmpty() && cmdletsToDelete.isEmpty()) {
      return;
    }
    List<CmdletInfo> cmdletInfos = new ArrayList<>();
    List<ActionInfo> actionInfos = new ArrayList<>();
    List<CmdletInfo> cmdletFinished = new ArrayList<>();

    int cmdletsToDeleteCount;
    synchronized (cmdletsToDelete) {
      cmdletsToDeleteCount = cmdletsToDelete.size();
      cmdletsToDelete.forEach(cmdlets::remove);
    }

    Set<Long> cmdletIds = new HashSet<>(cmdlets.keySet());
    for (long cmdletId : cmdletIds) {
      CmdletInfo cmdletInfo = cmdlets.remove(cmdletId);
      if (cmdletInfo.getState() != CmdletState.DISABLED) {
        cmdletInfos.add(cmdletInfo);

        cmdletInfo.getActionIds()
            .stream()
            .map(actions::get)
            .filter(Objects::nonNull)
            .forEach(actionInfos::add);
      }
      if (CmdletState.isTerminalState(cmdletInfo.getState())) {
        cmdletFinished.add(cmdletInfo);
      }
      if (cmdletInfos.size() >= cmdletCacheSyncBatchSize) {
        break;
      }
    }

    removeFinishedCmdlets(cmdletFinished);

    storeToMetastore(cmdletInfos, actionInfos);

    deleteCmdletsFromMetastore(cmdletsToDeleteCount);
  }

  private void storeToMetastore(List<CmdletInfo> cmdletInfos, List<ActionInfo> actionInfos) {
    if (!cmdletInfos.isEmpty()) {
      LOG.debug("Number of cmdlets {} to submit", cmdletInfos.size());
      try {
        metaStore.upsertActions(actionInfos);
        metaStore.upsertCmdlets(cmdletInfos);
      } catch (MetaStoreException e) {
        LOG.error("CmdletIds -> [ {} ], submit to DB error", cmdletInfos, e);
      }
    }
  }

  private void removeFinishedCmdlets(List<CmdletInfo> cmdletFinished) {
    for (CmdletInfo cmdletInfo : cmdletFinished) {
      unfinishedCmdlets.remove(cmdletInfo.getId());
      ruleCmdletTracker.stopTracking(cmdletInfo.getId());

      cmdletInfo.getActionIds().forEach(actions::remove);
    }
  }

  private void deleteCmdletsFromMetastore(int cmdletsToDeleteCount) {
    if (cmdletsToDeleteCount <= 0) {
      return;
    }

    int realCmdletsToDeleteCount = Math.min(cmdletsToDeleteCount, cmdletCacheSyncBatchSize);

    List<Long> cmdletsToDeleteBatch;
    synchronized (cmdletsToDelete) {
      cmdletsToDeleteBatch = new ArrayList<>(cmdletsToDelete.subList(0, realCmdletsToDeleteCount));
      cmdletsToDelete.removeAll(cmdletsToDeleteBatch);
    }

    if (!cmdletsToDeleteBatch.isEmpty()) {
      LOG.debug("Number of cmdlets {} to delete", cmdletsToDeleteBatch.size());
      try {
        metaStore.batchDeleteCmdlet(cmdletsToDeleteBatch);
        metaStore.batchDeleteCmdletActions(cmdletsToDeleteBatch);
      } catch (MetaStoreException e) {
        LOG.error("CmdletIds -> [ {} ], delete from DB error", cmdletsToDeleteBatch, e);
      }
    }
  }
}
