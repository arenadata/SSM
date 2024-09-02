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
package org.smartdata.server.engine.action;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.action.ActionException;
import org.smartdata.action.ActionRegistry;
import org.smartdata.action.SmartAction;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.SsmParseException;
import org.smartdata.hdfs.action.move.AbstractMoveFileAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.queries.sort.ActionSortField;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.request.ActionSearchRequest;
import org.smartdata.protocol.message.ActionStatus;
import org.smartdata.server.engine.cmdlet.CmdletManagerContext;
import org.smartdata.server.engine.cmdlet.InMemoryRegistry;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.smartdata.metastore.utils.MetaStoreUtils.logAndBuildMetastoreException;

public class ActionInfoHandler
    extends SearchableService<ActionSearchRequest, ActionInfo, ActionSortField> {
  private static final Logger LOG = LoggerFactory.getLogger(ActionInfoHandler.class);

  private final MetaStore metaStore;
  private AtomicLong maxActionId;

  private final InMemoryRegistry inMemoryRegistry;

  public ActionInfoHandler(CmdletManagerContext context) {
    super(context.getMetaStore().actionDao(), "actions");
    this.metaStore = context.getMetaStore();
    this.inMemoryRegistry = context.getInMemoryRegistry();
  }

  public void init() throws IOException {
    LOG.info("Initializing ...");
    try {
      maxActionId = new AtomicLong(metaStore.getMaxActionId());

      LOG.info("Initialized.");
    } catch (MetaStoreException e) {
      throw logAndBuildMetastoreException(
          LOG, "DB Connection error! Failed to get Max ActionId!", e);
    } catch (Exception t) {
      throw new IOException(t);
    }
  }

  public LaunchAction createLaunchAction(ActionInfo actionInfo) {
    Map<String, String> args = new HashMap<>(actionInfo.getArgs());
    return new LaunchAction(
        actionInfo.getActionId(),
        actionInfo.getActionName(),
        args);
  }

  public ActionInfo getActionInfo(long actionId) throws IOException {
    ActionInfo actionInfo = getActionInfoOrNull(actionId);

    if (actionInfo == null) {
      throw NotFoundException.forAction(actionId);
    }

    return actionInfo;
  }

  public ActionInfo getActionInfoOrNull(long actionId) throws IOException {
    ActionInfo actionInfo = getUnfinishedAction(actionId);
    try {
      return actionInfo == null
          ? metaStore.getActionById(actionId)
          : actionInfo;
    } catch (MetaStoreException e) {
      throw logAndBuildMetastoreException(
          LOG, "ActionId -> [ " + actionId + " ], get ActionInfo from DB error", e);
    }
  }

  public void store(ActionInfo actionInfo) {
    inMemoryRegistry.addAction(actionInfo);
  }

  public ActionInfo getUnfinishedAction(long actionId) {
    return inMemoryRegistry.getUnfinishedAction(actionId);
  }

  public List<ActionInfo> listNewCreatedActions(int actionNum) throws IOException {
    try {
      Map<Long, ActionInfo> actionInfos = new HashMap<>();
      for (ActionInfo info : metaStore.getNewCreatedActions(actionNum)) {
        actionInfos.put(info.getActionId(), info);
      }
      actionInfos.putAll(inMemoryRegistry.getUnfinishedActions());
      return new ArrayList<>(actionInfos.values());
    } catch (MetaStoreException e) {
      throw logAndBuildMetastoreException(
          LOG, "Get Finished Actions from DB error", e);
    }
  }

  public List<ActionInfo> getActions(List<Long> aids) throws IOException {
    try {
      return metaStore.getActions(aids);
    } catch (MetaStoreException e) {
      throw logAndBuildMetastoreException(
          LOG, "Get Actions by aid list from DB error: " + aids.toString(), e);
    }
  }

  public ActionInfo updateActionStatus(long actionId, ActionStatus status) {
    return inMemoryRegistry.updateAction(actionId,
        actionInfo -> updateActionStatusInternal(actionInfo, status));
  }

  public List<ActionInfo> createActionInfos(
      CmdletDescriptor cmdletDescriptor, CmdletInfo cmdletInfo) throws SsmParseException {

    validateActionNames(cmdletDescriptor);

    return IntStream.range(0, cmdletDescriptor.getActionSize())
        .mapToObj(actionIdx ->
            createInitialActionInfo(cmdletDescriptor, cmdletInfo, actionIdx))
        .collect(Collectors.toList());
  }

  private void updateActionStatusInternal(ActionInfo actionInfo, ActionStatus status) {
    if (actionInfo.isFinished()) {
      return;
    }

    actionInfo.setLog(status.getLog());
    actionInfo.setResult(status.getResult());
    if (!status.isFinished()) {
      actionInfo.setProgress(status.getPercentage());
      actionInfo.setFinishTime(System.currentTimeMillis());
    } else {
      actionInfo.setProgress(1.0F);
      actionInfo.setFinished(true);
      actionInfo.setCreateTime(status.getStartTime());
      actionInfo.setFinishTime(status.getFinishTime());
      if (status.getThrowable() != null) {
        actionInfo.setSuccessful(false);
      } else {
        actionInfo.setSuccessful(true);
        updateStorageIfNeeded(actionInfo);
      }
    }
  }

  private void updateStorageIfNeeded(ActionInfo info) {
    SmartAction action;
    try {
      action = ActionRegistry.createAction(info.getActionName());
    } catch (ActionException e) {
      LOG.error("Failed to create action from {}", info, e);
      return;
    }
    if (action instanceof AbstractMoveFileAction) {
      String policy = ((AbstractMoveFileAction) action).getStoragePolicy();
      Map<String, String> args = info.getArgs();
      if (policy == null) {
        policy = args.get(AbstractMoveFileAction.STORAGE_POLICY);
      }
      String path = args.get(AbstractMoveFileAction.FILE_PATH);
      try {
        String result = info.getResult();
        result = result == null ? "" : result;
        if (!result.contains("UpdateStoragePolicy=false")) {
          metaStore.updateFileStoragePolicy(path, policy);
        }
      } catch (MetaStoreException e) {
        LOG.error("Failed to update storage policy {} for file {}", policy, path, e);
      }
    }
  }

  private ActionInfo createInitialActionInfo(
      CmdletDescriptor cmdletDescriptor, CmdletInfo cmdletInfo, int actionIndex) {
    return ActionInfo.builder()
        .setActionId(maxActionId.getAndIncrement())
        .setCmdletId(cmdletInfo.getId())
        .setCreateTime(cmdletInfo.getGenerateTime())
        .setActionName(cmdletDescriptor.getActionName(actionIndex))
        .setArgs(cmdletDescriptor.getActionArgs(actionIndex))
        .build();
  }

  /**
   * Check if action names in cmdletDescriptor are correct.
   */
  private void validateActionNames(CmdletDescriptor cmdletDescriptor) throws SsmParseException {
    List<String> unknownActions = cmdletDescriptor.getActionNames()
        .stream()
        .filter(name -> !ActionRegistry.registeredAction(name))
        .collect(Collectors.toList());

    if (!unknownActions.isEmpty()) {
      throw new SsmParseException("Unknown actions used in cmdlet: " + unknownActions);
    }
  }
}
