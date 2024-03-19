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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.AbstractService;
import org.smartdata.action.ActionRegistry;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.DetailedRuleInfo;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.WhitelistHelper;
import org.smartdata.model.rule.RuleExecutorPluginManager;
import org.smartdata.model.rule.RulePluginManager;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.model.rule.TimeBasedScheduleInfo;
import org.smartdata.rule.parser.SmartRuleStringParser;
import org.smartdata.server.engine.rule.ErasureCodingPlugin;
import org.smartdata.server.engine.rule.ExecutorScheduler;
import org.smartdata.server.engine.rule.FileCopy2S3Plugin;
import org.smartdata.server.engine.rule.RuleExecutor;
import org.smartdata.server.engine.rule.RuleInfoRepo;
import org.smartdata.server.engine.rule.SmallFilePlugin;
import org.smartdata.server.engine.rule.copy.FileCopyDrPlugin;
import org.smartdata.server.engine.rule.copy.FileCopyScheduleStrategy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static org.smartdata.conf.SmartConfKeys.SMART_SYNC_SCHEDULE_STRATEGY_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_SYNC_SCHEDULE_STRATEGY_KEY;

/**
 * Manage and execute rules. We can have 'cache' here to decrease the needs to execute a SQL query.
 */
public class RuleManager extends AbstractService {
  public static final Logger LOG = LoggerFactory.getLogger(RuleManager.class.getName());

  private final ServerContext serverContext;
  private final StatesManager statesManager;
  private final CmdletManager cmdletManager;
  private final MetaStore metaStore;

  private boolean isClosed = false;

  private final ConcurrentHashMap<Long, RuleInfoRepo> mapRules;

  public ExecutorScheduler execScheduler;

  public RuleManager(
      ServerContext context, StatesManager statesManager, CmdletManager cmdletManager) {
    super(context);

    int numExecutors =
        context
            .getConf()
            .getInt(
                SmartConfKeys.SMART_RULE_EXECUTORS_KEY, SmartConfKeys.SMART_RULE_EXECUTORS_DEFAULT);
    execScheduler = new ExecutorScheduler(numExecutors);

    this.mapRules = new ConcurrentHashMap<>();
    this.statesManager = statesManager;
    this.cmdletManager = cmdletManager;
    this.serverContext = context;
    this.metaStore = context.getMetaStore();

    FileCopyScheduleStrategy copyScheduleStrategy = FileCopyScheduleStrategy.of(
        context.getConf().get(
            SMART_SYNC_SCHEDULE_STRATEGY_KEY,
            SMART_SYNC_SCHEDULE_STRATEGY_DEFAULT));

    if (serverContext.getServiceMode() == ServiceMode.HDFS) {
      RuleExecutorPluginManager.addPlugin(new FileCopyDrPlugin(
          context.getMetaStore(), copyScheduleStrategy));
      RuleExecutorPluginManager.addPlugin(new FileCopy2S3Plugin());
      RuleExecutorPluginManager.addPlugin(new SmallFilePlugin(context, cmdletManager));
      RuleExecutorPluginManager.addPlugin(new ErasureCodingPlugin(context));
    }
  }

  /**
   * Submit a rule to RuleManger.
   */
  public long submitRule(String rule, RuleState initState) throws IOException {
    LOG.debug("Received Rule -> [" + rule + "]");
    if (initState != RuleState.ACTIVE
        && initState != RuleState.DISABLED
        && initState != RuleState.NEW) {
      throw new IOException(
          "Invalid initState = "
              + initState
              + ", it MUST be one of ["
              + RuleState.ACTIVE
              + ", "
              + RuleState.NEW
              + ", "
              + RuleState.DISABLED
              + "]");
    }

    RuleTranslationResult tr = doCheckRule(rule);
    doCheckActions(tr.getCmdDescriptor());

    //check whitelist
    if (WhitelistHelper.isEnabled(serverContext.getConf())) {
      for (String path : tr.getPathPatterns()) {
        if (!WhitelistHelper.isInWhitelist(path, serverContext.getConf())) {
          throw new IOException("Path " + path + " is not in the whitelist.");
        }
      }
    }

    RuleInfo ruleInfo = RuleInfo.newBuilder()
        .setRuleText(rule)
        .setState(initState)
        .build();

    RulePluginManager.onAddingNewRule(ruleInfo, tr);

    try {
      metaStore.insertNewRule(ruleInfo);
    } catch (MetaStoreException e) {
      throw new IOException("RuleText = " + rule, e);
    }

    RuleInfoRepo infoRepo = new RuleInfoRepo(ruleInfo, metaStore, serverContext.getConf());
    mapRules.put(ruleInfo.getId(), infoRepo);
    submitRuleToScheduler(infoRepo.launchExecutor(this));

    RulePluginManager.onNewRuleAdded(ruleInfo, tr);

    return ruleInfo.getId();
  }

  private void doCheckActions(CmdletDescriptor cd) throws IOException {
    StringBuilder error = new StringBuilder();
    for (int i = 0; i < cd.getActionSize(); i++) {
      if (!ActionRegistry.registeredAction(cd.getActionName(i))) {
        error.append("Action '").append(cd.getActionName(i)).append("' not supported.\n");
      }
    }
    if (error.length() > 0) {
      throw new IOException(error.toString());
    }
  }

  private RuleTranslationResult doCheckRule(String rule) throws IOException {
    SmartRuleStringParser parser = new SmartRuleStringParser(rule, null, serverContext.getConf());
    return parser.translate();
  }

  public void checkRule(String rule) throws IOException {
    doCheckRule(rule);
  }

  public MetaStore getMetaStore() {
    return metaStore;
  }

  /**
   * Delete a rule in SSM. if dropPendingCmdlets equals false then the rule record will still be
   * kept in Table 'rules', the record will be deleted sometime later.
   *
   * @param dropPendingCmdlets pending cmdlets triggered by the rule will be discarded if true.
   */
  public void deleteRule(long ruleID, boolean dropPendingCmdlets) throws IOException {
    RuleInfoRepo infoRepo = checkIfExists(ruleID);
    try {
      if (dropPendingCmdlets && getCmdletManager() != null) {
        getCmdletManager().deleteCmdletByRule(ruleID);
      }
    } finally {
      infoRepo.delete();
    }
  }

  public void activateRule(long ruleID) throws IOException {
    RuleInfoRepo infoRepo = checkIfExists(ruleID);
    submitRuleToScheduler(infoRepo.activate(this));
  }

  public void disableRule(long ruleID, boolean dropPendingCmdlets) throws IOException {
    RuleInfoRepo infoRepo = checkIfExists(ruleID);
    infoRepo.disable();
    if (dropPendingCmdlets && getCmdletManager() != null) {
      getCmdletManager().dropRuleCmdlets(ruleID);
    }
  }

  private RuleInfoRepo checkIfExists(long ruleID) throws IOException {
    RuleInfoRepo infoRepo = mapRules.get(ruleID);
    if (infoRepo == null) {
      throw new IOException("Rule with ID = " + ruleID + " not found");
    }
    return infoRepo;
  }

  public RuleInfo getRuleInfo(long ruleID) throws IOException {
    RuleInfoRepo infoRepo = checkIfExists(ruleID);
    return infoRepo.getRuleInfo();
  }

  public List<DetailedRuleInfo> listRulesMoveInfo() throws IOException {
    try {
      return metaStore.listMoveRules();
    } catch (MetaStoreException e) {
      throw new IOException(e);
    }
  }

  public List<DetailedRuleInfo> listRulesSyncInfo() throws IOException {
    try {
      return metaStore.listSyncRules();
    } catch (MetaStoreException e) {
      throw new IOException(e);
    }
  }

  public List<RuleInfo> listRulesInfo() {
    Collection<RuleInfoRepo> infoRepos = mapRules.values();
    List<RuleInfo> retInfos = new ArrayList<>();
    for (RuleInfoRepo infoRepo : infoRepos) {
      RuleInfo info = infoRepo.getRuleInfo();
      if (info.getState() != RuleState.DELETED) {
        retInfos.add(info);
      }
    }
    return retInfos;
  }

  public void updateRuleInfo(
      long ruleId, RuleState rs, long lastCheckTime, long checkedCount, int cmdletsGen)
      throws IOException {
    RuleInfoRepo infoRepo = checkIfExists(ruleId);
    infoRepo.updateRuleInfo(rs, lastCheckTime, checkedCount, cmdletsGen);
  }

  public boolean isClosed() {
    return isClosed;
  }

  public StatesManager getStatesManager() {
    return statesManager;
  }

  public CmdletManager getCmdletManager() {
    return cmdletManager;
  }

  /**
   * Init RuleManager, this includes: 1. Load related data from local storage or HDFS 2. Initial
   *
   */
  @Override
  public void init() throws IOException {
    LOG.info("Initializing ...");
    // Load rules table
    List<RuleInfo> rules;
    try {
      rules = metaStore.getRuleInfo();
    } catch (MetaStoreException e) {
      LOG.error("Can not load rules from database", e);
      return;
    }
    for (RuleInfo rule : rules) {
      mapRules.put(rule.getId(), new RuleInfoRepo(rule, metaStore, serverContext.getConf()));
    }
    LOG.info("Initialized. Totally " + rules.size() + " rules loaded from DataBase.");
    if (LOG.isDebugEnabled()) {
      for (RuleInfo info : rules) {
        LOG.debug("\t" + info);
      }
    }
  }

  private boolean submitRuleToScheduler(RuleExecutor executor) {
    if (executor == null || executor.isExited()) {
      return false;
    }
    execScheduler.addPeriodicityTask(executor);
    return true;
  }

  /** Start services. */
  @Override
  public void start() throws IOException {
    LOG.info("Starting ...");
    // after StateManager be ready

    int numLaunched = 0;
    // Submit runnable rules to scheduler
    for (RuleInfoRepo infoRepo : mapRules.values()) {
      RuleInfo rule = infoRepo.getRuleInfoRef();
      if (rule.getState() == RuleState.ACTIVE) {
        RuleExecutor ruleExecutor = infoRepo.launchExecutor(this);
        RuleTranslationResult tr = ruleExecutor.getTranslateResult();
        TimeBasedScheduleInfo si = tr.getScheduleInfo();
        if (rule.getLastCheckTime() != 0) {
          si.setFirstCheckTime(rule.getLastCheckTime());
        }
        boolean sub = submitRuleToScheduler(ruleExecutor);
        numLaunched += sub ? 1 : 0;
      }
    }
    LOG.info("Started. " + numLaunched + " rules launched for execution.");
  }

  /** Stop services. */
  @Override
  public void stop() throws IOException {
    LOG.info("Stopping ...");
    isClosed = true;
    if (execScheduler != null) {
      execScheduler.shutdown();
    }
    LOG.info("Stopped.");
  }
}
