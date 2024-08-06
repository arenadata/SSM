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
import org.smartdata.exception.NotFoundException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.CmdletDao;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.request.CmdletSearchRequest;
import org.smartdata.protocol.message.CmdletStatus;
import org.smartdata.protocol.message.LaunchCmdlet;
import org.smartdata.server.engine.ActiveServerInfo;
import org.smartdata.server.engine.action.ActionInfoHandler;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class CmdletInfoHandler
    implements Searchable<CmdletSearchRequest, CmdletInfo, CmdletSortField> {
  private static final Logger LOG = LoggerFactory.getLogger(CmdletInfoHandler.class);

  private final MetaStore metaStore;
  private final CmdletDao cmdletDao;
  private final ActionInfoHandler actionInfoHandler;
  private final InMemoryRegistry inMemoryRegistry;
  private AtomicLong maxCmdletId;

  public CmdletInfoHandler(CmdletManagerContext context, ActionInfoHandler actionInfoHandler) {
    this.metaStore = context.getMetaStore();
    this.cmdletDao = metaStore.cmdletDao();
    this.inMemoryRegistry = context.getInMemoryRegistry();
    this.actionInfoHandler = actionInfoHandler;
  }

  public void init() throws IOException {
    LOG.info("Initializing ...");
    try {
      maxCmdletId = new AtomicLong(metaStore.getMaxCmdletId());
      LOG.info("Initialized.");
    } catch (MetaStoreException e) {
      LOG.error("DB Connection error! Failed to get Max CmdletId!", e);
      throw new IOException(e);
    }
  }

  public CmdletInfo createCmdletInfo(CmdletDescriptor cmdletDescriptor) {
    long submitTime = System.currentTimeMillis();
    return CmdletInfo.builder()
        .setId(maxCmdletId.getAndIncrement())
        .setRuleId(cmdletDescriptor.getRuleId())
        .setState(CmdletState.PENDING)
        .setParameters(cmdletDescriptor.getCmdletString())
        .setGenerateTime(submitTime)
        .setStateChangedTime(submitTime)
        .build();
  }

  public LaunchCmdlet createLaunchCmdlet(CmdletInfo cmdletInfo) {
    if (cmdletInfo == null) {
      return null;
    }

    List<LaunchAction> launchActions = cmdletInfo.getActionIds()
        .stream()
        .map(inMemoryRegistry::getUnfinishedAction)
        .filter(Objects::nonNull)
        .map(actionInfoHandler::createLaunchAction)
        .collect(Collectors.toList());

    return new LaunchCmdlet(cmdletInfo.getId(), launchActions);
  }

  public CmdletInfo getCmdletInfo(long cid) throws IOException {
    CmdletInfo cmdletInfo = getUnfinishedCmdlet(cid);
    try {
      return cmdletInfo == null
          ? metaStore.getCmdletById(cid)
          : cmdletInfo;
    } catch (MetaStoreException e) {
      LOG.error("CmdletId -> [ {} ], get CmdletInfo from DB error", cid, e);
      throw new IOException(e);
    }
  }

  public CmdletInfo getCmdletInfoOrThrow(long cid) throws IOException {
    return Optional.ofNullable(getCmdletInfo(cid))
        .orElseThrow(() -> NotFoundException.forCmdlet(cid));
  }

  public ActionInfo getSingleActionInfo(long cmdletId) throws IOException {
    Long actionId = Optional.ofNullable(getCmdletInfo(cmdletId))
        .map(CmdletInfo::getActionIds)
        .flatMap(actionIds -> actionIds.stream().findFirst())
        .orElseThrow(() -> new NotFoundException(
            "Cmdlet doesn't generate actions: " + cmdletId));

    return actionInfoHandler.getActionInfo(actionId);
  }

  public void storeUnfinished(CmdletInfo cmdletInfo) {
    inMemoryRegistry.addUnfinishedCmdlet(cmdletInfo);
    if (cmdletInfo.getState() == CmdletState.PENDING) {
      store(cmdletInfo);
    }
  }

  public void store(CmdletInfo cmdletInfo) {
    inMemoryRegistry.addCmdlet(cmdletInfo);
  }

  public CmdletInfo getUnfinishedCmdlet(long cmdletId) {
    return inMemoryRegistry.getUnfinishedCmdlet(cmdletId);
  }

  public List<CmdletInfo> listCmdletsInfo(
      long ruleId, CmdletState cmdletState) throws IOException {
    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .ruleId(ruleId)
        .state(cmdletState)
        .build();

    return searchWithCache(
        searchRequest,
        cmdletInfo -> cmdletInfo.getRuleId() == ruleId
            && cmdletInfo.getState().equals(cmdletState));
  }

  public List<CmdletInfo> listCmdletsInfo(long ruleId) throws IOException {
    CmdletSearchRequest searchRequest = CmdletSearchRequest.builder()
        .ruleId(ruleId)
        .build();
    return searchWithCache(
        searchRequest,
        cmdletInfo -> cmdletInfo.getRuleId() == ruleId);
  }

  public void onCmdletFinished(CmdletInfo cmdletInfo, boolean success) {
    for (Long aid : cmdletInfo.getActionIds()) {

      inMemoryRegistry.updateAction(aid, actionInfo -> {
        actionInfo.setProgress(1.0F);
        actionInfo.setFinished(true);
        actionInfo.setCreateTime(cmdletInfo.getStateChangedTime());
        actionInfo.setFinishTime(cmdletInfo.getStateChangedTime());
        actionInfo.setExecHost(ActiveServerInfo.getInstance().getId());
        actionInfo.setSuccessful(success);
      });
    }
  }

  public boolean deleteCmdlet(long cmdletId) throws IOException {
    try {
      boolean cmdletDeleted = metaStore.deleteCmdlet(cmdletId);
      metaStore.deleteCmdletActions(cmdletId);
      return cmdletDeleted;
    } catch (MetaStoreException e) {
      LOG.error("CmdletId -> [ {} ], delete from DB error", cmdletId, e);
      throw new IOException(e);
    }
  }

  public void updateCmdletExecHost(long cmdletId, String host) throws IOException {
    List<Long> actionIds = Optional.ofNullable(getCmdletInfo(cmdletId))
        .map(CmdletInfo::getActionIds)
        .orElseGet(Collections::emptyList);

    for (long id : actionIds) {
      ActionInfo action = actionInfoHandler.getActionInfo(id);
      if (action != null) {
        action.setExecHost(host);
      }
    }
  }

  /**
   * Delete all cmdlets related with ruleId.
   */
  public List<Long> deleteCmdletsByRule(long ruleId) throws IOException {
    List<Long> cmdletIds = listCmdletsInfo(ruleId)
        .stream()
        .map(CmdletInfo::getId)
        .collect(Collectors.toList());

    inMemoryRegistry.deleteCmdletsAsync(cmdletIds);
    return cmdletIds;
  }

  public List<Long> deleteUnfinishedCmdletsByRule(long ruleId) {
    List<Long> cmdletIds = inMemoryRegistry.getUnfinishedCmdlets()
        .values()
        .stream()
        .filter(cmdlet -> cmdlet.getRuleId() == ruleId
            && !CmdletState.isTerminalState(cmdlet.getState()))
        .map(CmdletInfo::getId)
        .collect(Collectors.toList());

    inMemoryRegistry.deleteCmdletsAsync(cmdletIds);
    return cmdletIds;
  }

  public CmdletInfo updateCmdletStatus(long cmdletId, CmdletStatus status) {
    return inMemoryRegistry.updateCmdlet(cmdletId, cmdlet -> updateCmdletStatus(cmdlet, status));
  }

  @Override
  public SearchResult<CmdletInfo> search(
      CmdletSearchRequest searchRequest, PageRequest<CmdletSortField> pageRequest) {
    return cmdletDao.search(searchRequest, pageRequest);
  }

  @Override
  public List<CmdletInfo> search(CmdletSearchRequest searchRequest) {
    return cmdletDao.search(searchRequest);
  }

  // todo after zeppelin removal check if we really need this
  // strongly consistent version of search
  private List<CmdletInfo> searchWithCache(
      CmdletSearchRequest searchRequest,
      Predicate<CmdletInfo> cachedCmdletInfoPicker) throws IOException {
    Map<Long, CmdletInfo> results;
    try {
      results = search(searchRequest)
          .stream()
          .collect(Collectors.toMap(
              CmdletInfo::getId,
              Function.identity()
          ));
    } catch (Exception exception) {
      throw new IOException("Error loading cmdlets from db", exception);
    }

    for (CmdletInfo info : inMemoryRegistry.getUnfinishedCmdlets().values()) {
      if (cachedCmdletInfoPicker.test(info)) {
        results.put(info.getId(), info);
      }
    }
    return new ArrayList<>(results.values());
  }

  private void updateCmdletStatus(CmdletInfo cmdletInfo, CmdletStatus status) {
    if (CmdletState.isTerminalState(cmdletInfo.getState())) {
      return;
    }
    CmdletState state = status.getCurrentState();
    cmdletInfo.setState(state);
    cmdletInfo.setStateChangedTime(status.getStateUpdateTime());
  }
}
