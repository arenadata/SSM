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
package org.smartdata.server.engine.rule;

import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.exception.NotFoundException;
import org.smartdata.exception.QueueFullException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.model.rule.TimeBasedScheduleInfo;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.data.ExecutionContext;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.smartdata.conf.SmartConfKeys.SMART_FS_TYPE_DEFAULT;
import static org.smartdata.metastore.dao.FileAccessPartitionDao.HDFS_FILE_ACCESS_TABLE;
import static org.smartdata.metastore.dao.FileAccessPartitionDao.OZONE_FILE_ACCESS_TABLE;

/**
 * Execute rule queries and return result.
 */
public class RuleExecutor implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(RuleExecutor.class.getName());

  private static final Pattern VAR_PATTERN = Pattern.compile("\\$([a-zA-Z_]+[a-zA-Z0-9_]*)");
  private static final Pattern CALL_PATTERN =
      Pattern.compile("\\$@([a-zA-Z_]+[a-zA-Z0-9_]*)\\(([a-zA-Z_][a-zA-Z0-9_]*)?\\)");

  private final RuleManager ruleManager;
  private final RuleTranslationResult translationResult;
  // since we run RuleExecutorPlugin methods for each launch of the RuleExecutor
  // we need to save the original rule translate result in order to use it
  // after rule activation after pause
  private final RuleTranslationResult originalTranslationResult;
  private final ExecutionContext executionCtx;
  private final MetaStore metastore;
  private final Stack<String> dynamicCleanups;
  private final List<RuleExecutorPlugin> executorPlugins;
  private final SmartConf conf;

  private volatile boolean exited;
  private long exitTime;

  public RuleExecutor(
      SmartConf conf,
      RuleManager ruleManager,
      ExecutionContext executionCtx,
      RuleTranslationResult translationResult,
      MetaStore metastore,
      List<RuleExecutorPlugin> executorPlugins) {
    this.conf = conf;
    this.ruleManager = ruleManager;
    this.executionCtx = executionCtx;
    this.metastore = metastore;
    this.translationResult = translationResult;
    this.originalTranslationResult = translationResult.copy();
    this.dynamicCleanups = new Stack<>();
    this.executorPlugins = executorPlugins;
    this.exited = false;
  }

  public RuleTranslationResult getTranslateResult() {
    return translationResult;
  }

  public RuleTranslationResult getOriginalTranslateResult() {
    return originalTranslationResult;
  }

  private String unfoldSqlStatement(String sql) {
    return unfoldVariables(unfoldFunctionCalls(sql));
  }

  private String unfoldVariables(String sql) {
    String ret = sql;
    executionCtx.setProperty("NOW", System.currentTimeMillis());
    Matcher m = VAR_PATTERN.matcher(sql);
    while (m.find()) {
      String rep = m.group();
      String varName = m.group(1);
      String value = executionCtx.getString(varName);
      ret = ret.replace(rep, value);
    }
    return ret;
  }

  private String unfoldFunctionCalls(String sql) {
    String ret = sql;
    Matcher m = CALL_PATTERN.matcher(sql);
    while (m.find()) {
      String rep = m.group();
      String funcName = m.group(1);
      String paraName = m.groupCount() == 2 ? m.group(2) : null;
      List<Object> params = translationResult.getParameter(paraName);
      String value = callFunction(funcName, params);
      ret = ret.replace(rep, value == null ? "" : value);
    }
    return ret;
  }

  public List<String> executeObjectIdsQuery() {
    int index = 0;
    List<String> ret = new ArrayList<>();
    for (String sql : translationResult.getSqlStatements()) {
      sql = unfoldSqlStatement(sql);
      try {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Rule " + executionCtx.getRuleId() + " --> " + sql);
        }
        if (index == translationResult.getRetSqlIndex()) {
          ret = metastore.executeObjectIdsQuery(sql);
        } else {
          sql = sql.trim();
          if (sql.length() > 5) {
            metastore.execute(sql);
          }
        }
        index++;
      } catch (MetaStoreException e) {
        LOG.error("Rule " + executionCtx.getRuleId() + " exception", e);
        return ret;
      }
    }

    while (!dynamicCleanups.empty()) {
      String sql = dynamicCleanups.pop();
      try {
        metastore.execute(sql);
      } catch (MetaStoreException e) {
        LOG.error("Rule " + executionCtx.getRuleId() + " exception", e);
      }
    }
    return ret;
  }

  public String callFunction(String funcName, List<Object> parameters) {
    try {
      Method m = getClass().getMethod(funcName, List.class);
      return (String) (m.invoke(this, parameters));
    } catch (Exception e) {
      LOG.error("Rule " + executionCtx.getRuleId() + " exception when call " + funcName, e);
      return null;
    }
  }

  public String genVirtualAccessCountTableTopValue(List<Object> parameters) {
    genVirtualAccessCountTableValue(parameters, true);
    return null;
  }

  public String genVirtualAccessCountTableBottomValue(List<Object> parameters) {
    genVirtualAccessCountTableValue(parameters, false);
    return null;
  }

  private void genVirtualAccessCountTableValue(List<Object> parameters, boolean top) {
    List<Object> paraList = (List<Object>) parameters.get(0);
    String table = (String) parameters.get(1);
    String var = (String) parameters.get(2);
    Long num = (Long) paraList.get(1);
    String sql0 = String.format(
        "SELECT %s(count) FROM ( SELECT * FROM %s ORDER BY count %sLIMIT %d ) AS %s_TMP;",
        top ? "min" : "max", table, top ? "DESC " : "", num, table);
    Long count = null;
    try {
      count = metastore.queryForLong(sql0);
    } catch (MetaStoreException e) {
      LOG.error("Get " + (top ? "top" : "bottom") + " access count from table '"
          + table + "' error.", e);
    }
    executionCtx.setProperty(var, count == null ? 0L : count);
  }

  public String genVirtualAccessCountTable(List<Object> parameters) {
    List<Object> paraList = (List<Object>) parameters.get(0);
    String newTable = (String) parameters.get(1);
    long interval = paraList.isEmpty() ? 0L : (long) paraList.get(0);
    String countFilter = "";
    long currentTimeMillis = System.currentTimeMillis();
    return generateSQL(conf, newTable, countFilter, metastore, currentTimeMillis - interval,
        currentTimeMillis);
  }

  // todo refactor dynamic calls to access count tables
  @VisibleForTesting
  static String generateSQL(
      SmartConf conf,
      String newTable,
      String countFilter,
      MetaStore adapter,
      long startTime,
      long endTime) {
    String sqlFinal, sqlCreate;
    sqlCreate = "CREATE TABLE " + newTable + "(fid INTEGER NOT NULL, count INTEGER NOT NULL);";
    try {
      adapter.execute(sqlCreate);
    } catch (MetaStoreException e) {
      LOG.error("Cannot create table " + newTable, e);
    }

    String fileAccessTable = conf.getFsType() == SMART_FS_TYPE_DEFAULT
        ? HDFS_FILE_ACCESS_TABLE
        : OZONE_FILE_ACCESS_TABLE;

    String sqlCountFilter =
        (countFilter == null || countFilter.isEmpty())
            ? ""
            : " HAVING count(*) " + countFilter;
    sqlFinal = "INSERT INTO " + newTable + " SELECT fid, count(*) AS count FROM " + fileAccessTable + "\n"
        + "WHERE access_time >= " + startTime + " AND access_time <= " + endTime
        + " GROUP BY fid" + sqlCountFilter + " ;";
    return sqlFinal;
  }

  @Override
  public void run() {
    long startCheckTime = System.currentTimeMillis();
    if (exited) {
      exitSchedule();
    }

    if (!translationResult.getScheduleInfo().isExecutable(startCheckTime)) {
      return;
    }

    long rid = executionCtx.getRuleId();
    try {
      if (ruleManager.isClosed()) {
        exitSchedule();
      }

      long endCheckTime;
      int numCmdSubmitted = 0;
      List<String> objectIds = new ArrayList<>();

      RuleInfo info;
      try {
        info = ruleManager.getRuleInfo(rid);
      } catch (NotFoundException notFoundException) {
        exitSchedule();
        return;
      }

      boolean continueExecution = true;
      for (RuleExecutorPlugin plugin : executorPlugins) {
        continueExecution = plugin.preExecution(info, translationResult);
        if (!continueExecution) {
          break;
        }
      }

      RuleState state = info.getState();
      if (exited
          || state == RuleState.DELETED
          || state == RuleState.FINISHED
          || state == RuleState.DISABLED) {
        exitSchedule();
      }
      TimeBasedScheduleInfo scheduleInfo = translationResult.getScheduleInfo();

      if (!scheduleInfo.isOnce() && scheduleInfo.getEndTime() != TimeBasedScheduleInfo.FOR_EVER) {
        boolean befExit = false;
        if (scheduleInfo.isOneShot()) {
          // The subScheduleTime is set in triggering time.
          if (scheduleInfo.getSubScheduleTime() > scheduleInfo.getEndTime()) {
            befExit = true;
          }
        } else if (startCheckTime - scheduleInfo.getEndTime() > 0) {
          befExit = true;
        }

        if (befExit) {
          LOG.info("Rule " + executionCtx.getRuleId() + " exit rule executor due to time passed");
          ruleManager.updateRuleInfo(rid, RuleState.FINISHED, startCheckTime, 0, 0);
          exitSchedule();
        }
      }

      if (continueExecution) {
        objectIds = executeObjectIdsQuery();
        if (exited) {
          exitSchedule();
        }
      }
      endCheckTime = System.currentTimeMillis();
      if (continueExecution) {
        for (RuleExecutorPlugin plugin : executorPlugins) {
          objectIds = plugin.preSubmitCmdlet(info, objectIds);
        }
        numCmdSubmitted = submitCmdlets(info, objectIds);
      }
      ruleManager.updateRuleInfo(rid, null, startCheckTime, 1, numCmdSubmitted);

      long endProcessTime = System.currentTimeMillis();
      if (endProcessTime - startCheckTime > 2000 || LOG.isDebugEnabled()) {
        LOG.warn(
            "Rule "
                + executionCtx.getRuleId()
                + " execution took "
                + (endProcessTime - startCheckTime)
                + "ms. QueryTime = "
                + (endCheckTime - startCheckTime)
                + "ms, SubmitTime = "
                + (endProcessTime - endCheckTime)
                + "ms, fileNum = "
                + numCmdSubmitted
                + ".");
      }

      if (scheduleInfo.isOneShot()) {
        ruleManager.updateRuleInfo(rid, RuleState.FINISHED, startCheckTime, 0, 0);
        exitSchedule();
      }

      if (endProcessTime + scheduleInfo.getBaseEvery() > scheduleInfo.getEndTime()) {
        LOG.info("Rule " + executionCtx.getRuleId() + " exit rule executor due to finished");
        ruleManager.updateRuleInfo(rid, RuleState.FINISHED, startCheckTime, 0, 0);
        exitSchedule();
      }

      if (exited) {
        exitSchedule();
      }
    } catch (IOException e) {
      LOG.error("Rule " + executionCtx.getRuleId() + " exception", e);
    }
  }

  private void exitSchedule() {
    // throw an exception
    exitTime = System.currentTimeMillis();
    exited = true;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Rule " + executionCtx.getRuleId() + " exit rule executor.");
    }
    // todo why do we exit with exception?
    throw new RuntimeException("Rule executor exit exception");
  }

  private int submitCmdlets(RuleInfo ruleInfo, List<String> objectIds) {
    long ruleId = ruleInfo.getId();
    if (objectIds == null || objectIds.isEmpty() || ruleManager.getCmdletManager() == null) {
      return 0;
    }
    int nSubmitted = 0;
    CmdletDescriptor templateCmdlet = translationResult.getCmdDescriptor();
    for (String objectId : objectIds) {
      if (exited) {
        break;
      }
      try {
        CmdletDescriptor cmdletDescriptor = new CmdletDescriptor(templateCmdlet);
        cmdletDescriptor.setRuleId(ruleId);
        // for compatibility with old cmdlets and schedulers
        cmdletDescriptor.setCmdletParameter(CmdletDescriptor.HDFS_FILE_PATH, objectId);
        cmdletDescriptor.setCmdletParameter(CmdletDescriptor.OBJECT_ID, objectId);
        for (RuleExecutorPlugin plugin : executorPlugins) {
          cmdletDescriptor = plugin.preSubmitCmdletDescriptor(
              ruleInfo, translationResult, cmdletDescriptor);
        }
        long cid = ruleManager.getCmdletManager()
            .submitCmdlet(cmdletDescriptor, ruleInfo.getOwner());
        // Not really submitted if cid is -1.
        if (cid != -1) {
          nSubmitted++;
        }
      } catch (QueueFullException e) {
        break;
      } catch (IOException e) {
        // it's common here, ignore this and continue submit
        LOG.debug("Failed to submit cmdlet for objectId {} due to Exception", objectId, e);
      }
    }
    return nSubmitted;
  }

  public boolean isExited() {
    return exited;
  }

  public void setExited() {
    exitTime = System.currentTimeMillis();
    exited = true;
  }
}
