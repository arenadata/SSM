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

import com.google.common.collect.ListMultimap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.CmdletState;
import org.smartdata.model.ExecutorType;
import org.smartdata.model.LaunchAction;
import org.smartdata.model.action.ActionScheduler;
import org.smartdata.protocol.message.ActionStatus;
import org.smartdata.protocol.message.CmdletStatus;
import org.smartdata.protocol.message.LaunchCmdlet;
import org.smartdata.server.cluster.ActiveServerNodeCmdletMetrics;
import org.smartdata.server.cluster.ClusterNodeMetricsProvider;
import org.smartdata.server.cluster.NodeCmdletMetrics;
import org.smartdata.server.engine.ActiveServerInfo;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.message.AddNodeMessage;
import org.smartdata.server.engine.message.RemoveNodeMessage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class CmdletDispatcher implements ClusterNodeMetricsProvider {
  private static final Logger LOG = LoggerFactory.getLogger(CmdletDispatcher.class);
  private final Queue<Long> pendingCmdlets;
  private final CmdletManager cmdletManager;
  private final List<Long> runningCmdlets;
  private final Map<Long, LaunchCmdlet> idToLaunchCmdlet;
  private final ListMultimap<String, ActionScheduler> schedulers;

  private final ScheduledExecutorService executorService;

  private final CmdletExecutorService[] cmdExecServices;
  private final int[] executorsByType;
  private int totalExecutorInstances;
  private final AtomicInteger[] slotsLeftByExecutorType;
  private final AtomicInteger totalSlotsLeft;
  private final AtomicInteger totalSlots;

  private final Map<Long, ExecutorType> dispatchedToExecutorType;
  private final boolean disableLocalExec;
  private final boolean logDispatchResult;
  private final DispatchTask[] dispatchTasks;
  private final int outputDispatchMetricsInterval; // 0 means no output

  private final AtomicInteger currentExecutorInstanceIdx;

  private final Map<String, AtomicInteger> regNodes;
  private final Map<String, NodeCmdletMetrics> regNodeInfos;

  private final List<List<String>> cmdExecSrvNodeIds;
  private final String[] completeOn;

  private final SmartConf conf;

  public CmdletDispatcher(ServerContext smartContext, CmdletManager cmdletManager,
      Queue<Long> scheduledCmdlets, Map<Long, LaunchCmdlet> idToLaunchCmdlet,
      List<Long> runningCmdlets, ListMultimap<String, ActionScheduler> schedulers) {
    this.conf = smartContext.getConf();
    this.cmdletManager = cmdletManager;
    this.pendingCmdlets = scheduledCmdlets;
    this.runningCmdlets = runningCmdlets;
    this.idToLaunchCmdlet = idToLaunchCmdlet;
    this.schedulers = schedulers;

    this.currentExecutorInstanceIdx = new AtomicInteger(0);
    this.regNodes = new HashMap<>();
    this.regNodeInfos = new HashMap<>();
    this.cmdExecSrvNodeIds = new ArrayList<>();
    this.completeOn = new String[ExecutorType.values().length];
    this.totalSlots = new AtomicInteger();
    this.totalSlotsLeft = new AtomicInteger();

    this.cmdExecServices = new CmdletExecutorService[ExecutorType.values().length];
    this.executorsByType = new int[ExecutorType.values().length];
    this.slotsLeftByExecutorType = new AtomicInteger[ExecutorType.values().length];
    for (int i = 0; i < slotsLeftByExecutorType.length; i++) {
      slotsLeftByExecutorType[i] = new AtomicInteger(0);
      cmdExecSrvNodeIds.add(new ArrayList<>());
    }
    this.totalExecutorInstances = 0;
    this.dispatchedToExecutorType = new ConcurrentHashMap<>();

    this.disableLocalExec = conf.getBoolean(
        SmartConfKeys.SMART_ACTION_LOCAL_EXECUTION_DISABLED_KEY,
        SmartConfKeys.SMART_ACTION_LOCAL_EXECUTION_DISABLED_DEFAULT);

    this.logDispatchResult = conf.getBoolean(
        SmartConfKeys.SMART_CMDLET_DISPATCHER_LOG_DISP_RESULT_KEY,
        SmartConfKeys.SMART_CMDLET_DISPATCHER_LOG_DISP_RESULT_DEFAULT);
    int numDisp = conf.getInt(SmartConfKeys.SMART_CMDLET_DISPATCHERS_KEY,
        SmartConfKeys.SMART_CMDLET_DISPATCHERS_DEFAULT);
    if (numDisp <= 0) {
      numDisp = 1;
    }
    this.dispatchTasks = new DispatchTask[numDisp];
    for (int i = 0; i < numDisp; i++) {
      dispatchTasks[i] = new DispatchTask(this);
    }
    this.executorService = smartContext.getMetricsFactory().wrap(
        Executors.newScheduledThreadPool(numDisp + 1), "cmdletDispatcherExecutor");
    this.outputDispatchMetricsInterval = conf.getInt(
        SmartConfKeys.SMART_CMDLET_DISPATCHER_LOG_DISP_METRICS_INTERVAL_KEY,
        SmartConfKeys.SMART_CMDLET_DISPATCHER_LOG_DISP_METRICS_INTERVAL_DEFAULT);
  }

  public void registerExecutorService(CmdletExecutorService executorService) {
    // No need to register for disabled local executor service.
    if (executorService.getExecutorType() == ExecutorType.LOCAL && disableLocalExec) {
      return;
    }
    this.cmdExecServices[executorService.getExecutorType().ordinal()] = executorService;
  }

  public boolean canDispatchMore() {
    return getTotalSlotsLeft() > 0;
  }

  public void stopCmdletOnExecutor(long cmdletId) {
    Optional.ofNullable(dispatchedToExecutorType.get(cmdletId))
        .map(executorType -> cmdExecServices[executorType.ordinal()])
        .ifPresent(executorService -> executorService.stop(cmdletId));
  }

  //Todo: move this function to a proper place
  public void shutDownExecutorServices() {
    for (CmdletExecutorService service : cmdExecServices) {
      if (service != null) {
        try {
          service.shutdown();
        } catch (Exception e) {
          LOG.error("Error shutting down dispatcher executor service", e);
        }
      }
    }
  }

  public LaunchCmdlet getNextCmdletToRun() {
    Long cmdletId = pendingCmdlets.poll();
    if (cmdletId == null) {
      return null;
    }
    LaunchCmdlet launchCmdlet = idToLaunchCmdlet.get(cmdletId);
    runningCmdlets.add(cmdletId);
    return launchCmdlet;
  }

  private void updateCmdActionStatus(LaunchCmdlet cmdlet, String host) {
    if (cmdletManager != null) {
      try {
        cmdletManager.updateCmdletExecHost(cmdlet.getCmdletId(), host);
      } catch (IOException e) {
        // Ignore this
      }
    }

    try {
      LaunchAction action;
      ActionStatus actionStatus;
      for (int i = 0; i < cmdlet.getLaunchActions().size(); i++) {
        action = cmdlet.getLaunchActions().get(i);
        actionStatus = new ActionStatus(cmdlet.getCmdletId(),
            i == cmdlet.getLaunchActions().size() - 1,
            action.getActionId(), System.currentTimeMillis());
        cmdletManager.onActionStatusUpdate(actionStatus);
      }
      CmdletStatus cmdletStatus = new CmdletStatus(cmdlet.getCmdletId(),
          System.currentTimeMillis(), CmdletState.DISPATCHED);
      cmdletManager.onCmdletStatusUpdate(cmdletStatus);
    } catch (IOException e) {
      LOG.info("update status failed.", e);
    }
  }

  private class DispatchTask implements Runnable {
    private final CmdletDispatcher dispatcher;
    private int statRound = 0;
    private int statFail = 0;
    private int statDispatched = 0;
    private int statNoMoreCmdlet = 0;
    private int statFull = 0;
    private LaunchCmdlet launchCmdlet = null;

    private final int[] dispInstIdxs = new int[ExecutorType.values().length];

    public DispatchTask(CmdletDispatcher dispatcher) {
      this.dispatcher = dispatcher;
    }

    public CmdletDispatcherStat getStat() {
      CmdletDispatcherStat stat = new CmdletDispatcherStat(statRound, statFail,
          statDispatched, statNoMoreCmdlet, statFull);
      statRound = 0;
      statFail = 0;
      statDispatched = 0;
      statFull = 0;
      statNoMoreCmdlet = 0;
      return stat;
    }

    @Override
    public void run() {
      statRound++;

      if (totalExecutorInstances == 0) {
        LOG.warn("No available executor service to execute action! "
            + "This can happen when only one smart server is running and "
            + "`smart.action.local.execution.disabled` is set to true.");
        return;
      }

      if (!dispatcher.canDispatchMore()) {
        statFull++;
        return;
      }

      boolean redisp = launchCmdlet != null;
      boolean disped;
      while (resvExecSlot()) {
        disped = false;
        try {
          if (launchCmdlet == null) {
            launchCmdlet = getNextCmdletToRun();
          }
          if (launchCmdlet == null) {
            statNoMoreCmdlet++;
            break;
          } else {
            if (!redisp) {
              cmdletPreExecutionProcess(launchCmdlet);
            } else {
              redisp = false;
            }
            if (!dispatch(launchCmdlet)) {
              if (LOG.isDebugEnabled()) {
                LOG.debug("Stop this round dispatch due : {}", launchCmdlet);
              }
              statFail++;
              break;
            }
            disped = true;
            statDispatched++;
          }
        } catch (Throwable t) {
          LOG.error("Cmdlet dispatcher error", t);
        } finally {
          if (!disped) {
            freeExecSlot();
          } else {
            launchCmdlet = null;
          }
        }
      }
    }

    private boolean dispatch(LaunchCmdlet cmdlet) {
      int mod = currentExecutorInstanceIdx.incrementAndGet() % totalExecutorInstances;
      int executorTypeIdx = 0;

      for (int nround = 0; nround < 2 && mod >= 0; ++nround) {
        for (executorTypeIdx = 0; executorTypeIdx < executorsByType.length; ++executorTypeIdx) {
          mod -= executorsByType[executorTypeIdx];
          if (mod < 0) {
            break;
          }
        }
        try {
          Thread.sleep(10);
        } catch (InterruptedException e) {
          // ignore
        }
      }

      if (mod >= 0) {
        return false;
      }

      CmdletExecutorService selectedExecutor = null;
      for (int i = 0; i < ExecutorType.values().length; i++) {
        executorTypeIdx = executorTypeIdx % ExecutorType.values().length;
        int executorFreeSlots;
        do {
          executorFreeSlots = slotsLeftByExecutorType[executorTypeIdx].get();
          if (executorFreeSlots > 0) {
            if (slotsLeftByExecutorType[executorTypeIdx].compareAndSet(executorFreeSlots, executorFreeSlots - 1)) {
              selectedExecutor = cmdExecServices[executorTypeIdx];
              break;
            }
          }
        } while (executorFreeSlots > 0);

        if (selectedExecutor != null) {
          break;
        }
        executorTypeIdx++;
      }

      if (selectedExecutor == null) {
        LOG.error("No cmdlet executor service available. {}", cmdlet);
        return false;
      }

      int selectedExecutorTypeIdx = selectedExecutor.getExecutorType().ordinal();

      boolean sFlag = true;
      String nodeId;
      AtomicInteger counter;
      do {
        dispInstIdxs[selectedExecutorTypeIdx] = (dispInstIdxs[selectedExecutorTypeIdx] + 1)
            % cmdExecSrvNodeIds.get(selectedExecutorTypeIdx).size();
        nodeId = cmdExecSrvNodeIds.get(selectedExecutorTypeIdx).get(dispInstIdxs[selectedExecutorTypeIdx]);
        counter = regNodes.get(nodeId);
        int left = counter.get();
        if (left > 0) {
          if (counter.compareAndSet(left, left - 1)) {
            break;
          }
        }

        if (sFlag && completeOn[selectedExecutorTypeIdx] != null) {
          dispInstIdxs[selectedExecutorTypeIdx] = cmdExecSrvNodeIds.get(selectedExecutorTypeIdx)
              .indexOf(completeOn[selectedExecutorTypeIdx]);
          sFlag = false;
        }
      } while (true);
      cmdlet.setNodeId(nodeId);

      boolean dispSucc = false;
      try {
        selectedExecutor.execute(cmdlet);
        dispSucc = true;
      } catch (Exception e) {
        LOG.error("Error dispatching cmdlet: {}", cmdlet.getCmdletId(), e);
      } finally {
        if (!dispSucc) {
          counter.incrementAndGet();
          slotsLeftByExecutorType[executorTypeIdx].incrementAndGet();
        }
      }
      if (!dispSucc) {
        return false;
      }

      NodeCmdletMetrics metrics = regNodeInfos.get(nodeId);
      if (metrics != null) {
        metrics.incCmdletsInExecution();
      }
      updateCmdActionStatus(cmdlet, nodeId);
      dispatchedToExecutorType.put(cmdlet.getCmdletId(), selectedExecutor.getExecutorType());

      if (logDispatchResult) {
        LOG.info("Dispatching cmdlet->[{}] to executor: {}", cmdlet.getCmdletId(), nodeId);
      }
      return true;
    }
  }

  private class LogStatTask implements Runnable {
    public DispatchTask[] tasks;
    private long lastReportNoExecutor = 0;
    private long lastInfo = System.currentTimeMillis();

    public LogStatTask(DispatchTask[] tasks) {
      this.tasks = tasks;
    }

    @Override
    public void run() {
      long curr = System.currentTimeMillis();
      CmdletDispatcherStat stat = new CmdletDispatcherStat();
      for (DispatchTask task : tasks) {
        stat.add(task.getStat());
      }

      if (!(stat.getStatDispatched() == 0 && stat.getStatRound() == stat.getStatNoMoreCmdlet())) {
        if (totalExecutorInstances != 0 || stat.getStatFull() != 0) {
          LOG.info("timeInterval={} statRound={} statFail={} statDispatched={} "
                  + "statNoMoreCmdlet={} statFull={} pendingCmdlets={} numExecutor={}",
              curr - lastInfo, stat.getStatRound(), stat.getStatFail(), stat.getStatDispatched(),
              stat.getStatNoMoreCmdlet(), stat.getStatFull(), pendingCmdlets.size(),
              totalExecutorInstances);
        } else {
          if (curr - lastReportNoExecutor >= 600 * 1000L) {
            LOG.info("No cmdlet executor. pendingCmdlets={}", pendingCmdlets.size());
            lastReportNoExecutor = curr;
          }
        }
      }
      lastInfo = System.currentTimeMillis();
    }
  }

  public void cmdletPreExecutionProcess(LaunchCmdlet cmdlet) {
    for (LaunchAction action : cmdlet.getLaunchActions()) {
      for (ActionScheduler p : schedulers.get(action.getActionType())) {
        p.onPreDispatch(cmdlet, action);
      }
    }
  }

  public void onCmdletFinished(long cmdletId) {
    synchronized (dispatchedToExecutorType) {
      if (dispatchedToExecutorType.containsKey(cmdletId)) {
        LaunchCmdlet cmdlet = idToLaunchCmdlet.get(cmdletId);
        if (cmdlet == null) {
          return;
        }
        if (regNodes.get(cmdlet.getNodeId()) != null) {
          regNodes.get(cmdlet.getNodeId()).incrementAndGet();
        }

        NodeCmdletMetrics metrics = regNodeInfos.get(cmdlet.getNodeId());
        if (metrics != null) {
          metrics.finishCmdlet();
        }

        ExecutorType t = dispatchedToExecutorType.remove(cmdletId);
        updateSlotsLeft(t.ordinal(), 1);
        completeOn[t.ordinal()] = cmdlet.getNodeId();
      }
    }
  }

  public void onNodeAdded(AddNodeMessage msg) {
    // New standby server can be added to an active SSM cluster by
    // executing start-standby-server.sh.
    if (msg.getNodeInfo().getExecutorType() == ExecutorType.REMOTE_SSM) {
      conf.addServerHosts(msg.getNodeInfo().getHost());
    }

    // New agent can be added to an active SSM cluster by executing
    // start-agent.sh.
    if (msg.getNodeInfo().getExecutorType() == ExecutorType.AGENT) {
      conf.addAgentHost(msg.getNodeInfo().getHost());
    }

    int nodeExecutorsCount = msg.getCmdletExecutorsCount();

    synchronized (executorsByType) {
      String nodeId = msg.getNodeInfo().getId();

      if (regNodes.containsKey(nodeId)) {
        LOG.warn("Skip duplicate add node for {}", msg.getNodeInfo());
        return;
      }

      NodeCmdletMetrics metrics = msg.getNodeInfo().getExecutorType() == ExecutorType.LOCAL
          ? new ActiveServerNodeCmdletMetrics()
          : new NodeCmdletMetrics();

      metrics.setNumExecutors(nodeExecutorsCount);
      metrics.setRegistrationTime(System.currentTimeMillis());
      metrics.setNodeInfo(msg.getNodeInfo());

      regNodes.put(nodeId, new AtomicInteger(nodeExecutorsCount));
      regNodeInfos.put(nodeId, metrics);

      // Ignore local executor if it is disabled.
      if (disableLocalExec && msg.getNodeInfo().getExecutorType()
          == ExecutorType.LOCAL) {
        return;
      }

      int executorTypeIdx = msg.getNodeInfo().getExecutorType().ordinal();
      cmdExecSrvNodeIds.get(executorTypeIdx).add(nodeId);
      ++executorsByType[executorTypeIdx];
      ++totalExecutorInstances;
      totalSlots.addAndGet(nodeExecutorsCount);
      updateSlotsLeft(executorTypeIdx, nodeExecutorsCount);
    }

    LOG.info("Node {} added", msg.getNodeInfo());
  }

  public void onNodeRemoved(RemoveNodeMessage msg) {
    synchronized (executorsByType) {
      String nodeId = msg.getNodeInfo().getId();
      NodeCmdletMetrics nodeCmdletMetrics = regNodeInfos.get(nodeId);

      if (!regNodes.containsKey(nodeId) || nodeCmdletMetrics == null) {
        LOG.warn("Skip duplicate remove node for {}", msg.getNodeInfo());
        return;
      }

      int nodeExecutorsCount = nodeCmdletMetrics.getNumExecutors();

      regNodes.remove(nodeId);
      regNodeInfos.remove(nodeId);

      // Ignore local executor if it is disabled.
      if (disableLocalExec && msg.getNodeInfo().getExecutorType()
          == ExecutorType.LOCAL) {
        return;
      }

      int executorTypeIdx = msg.getNodeInfo().getExecutorType().ordinal();
      cmdExecSrvNodeIds.get(executorTypeIdx).remove(nodeId);
      --executorsByType[executorTypeIdx];
      --totalExecutorInstances;
      totalSlots.addAndGet(-nodeExecutorsCount);
      updateSlotsLeft(executorTypeIdx, -nodeExecutorsCount);
    }

    LOG.info("Node {} removed", msg.getNodeInfo());
  }

  private void updateSlotsLeft(int executorTypeIdx, int delta) {
    slotsLeftByExecutorType[executorTypeIdx].addAndGet(delta);
    totalSlotsLeft.addAndGet(delta);
  }

  public int getTotalSlotsLeft() {
    return totalSlotsLeft.get();
  }

  public boolean resvExecSlot() {
    if (totalSlotsLeft.decrementAndGet() >= 0) {
      return true;
    }
    totalSlotsLeft.incrementAndGet();
    return false;
  }

  public void freeExecSlot() {
    totalSlotsLeft.incrementAndGet();
  }

  public int getTotalSlots() {
    return totalSlots.get();
  }

  @Override
  public Collection<NodeCmdletMetrics> getNodeMetrics() {
    maybeUpdateActiveNodeMetrics();
    return new ArrayList<>(regNodeInfos.values());
  }

  public void start() {
    // Instantiate and register LocalCmdletExecutorService.
    CmdletExecutorService exe =
        new LocalCmdletExecutorService(conf, cmdletManager);
    exe.start();
    registerExecutorService(exe);

    CmdletDispatcherHelper.getInst().register(this);
    long idx = 0;
    for (DispatchTask task : dispatchTasks) {
      executorService.scheduleAtFixedRate(task, idx * 200 / dispatchTasks.length,
          100, TimeUnit.MILLISECONDS);
      idx++;
    }
    if (outputDispatchMetricsInterval > 0) {
      executorService.scheduleAtFixedRate(new LogStatTask(dispatchTasks),
          5000, outputDispatchMetricsInterval, TimeUnit.MILLISECONDS);
    }
  }

  public void stop() {
    CmdletDispatcherHelper.getInst().unregister();
    executorService.shutdownNow();
  }

  private void maybeUpdateActiveNodeMetrics() {
    Optional.ofNullable(ActiveServerInfo.getInstance().getId())
        .map(regNodeInfos::get)
        .map(ActiveServerNodeCmdletMetrics.class::cast)
        .ifPresent(this::updateActiveNodeMetrics);
  }

  private void updateActiveNodeMetrics(ActiveServerNodeCmdletMetrics metrics) {
    metrics.setNumPendingDispatch(pendingCmdlets.size());
    metrics.setMaxPendingDispatch(getTotalSlotsLeft() + (int) (getTotalSlots() * 0.2));
    metrics.setMaxInExecution(getTotalSlots());
    metrics.setNumInExecution(getTotalSlots() - getTotalSlotsLeft());
    cmdletManager.updateNodeCmdletMetrics(metrics);
  }
}
