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
import org.smartdata.exception.QueueFullException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.AccessCountTable;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.model.rule.RuleExecutorPluginManager;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.model.rule.TimeBasedScheduleInfo;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.data.ExecutionContext;

import java.io.IOException;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Execute rule queries and return result. */
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

  private volatile boolean exited;
  private long exitTime;

  public RuleExecutor(RuleManager ruleManager, ExecutionContext executionCtx,
                      RuleTranslationResult translationResult, MetaStore metastore) {
    this.ruleManager = ruleManager;
    this.executionCtx = executionCtx;
    this.metastore = metastore;
    this.translationResult = translationResult;
    this.originalTranslationResult = translationResult.copy();
    this.dynamicCleanups = new Stack<>();
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

  public List<String> executeFileRuleQuery() {
    int index = 0;
    List<String> ret = new ArrayList<>();
    for (String sql : translationResult.getSqlStatements()) {
      sql = unfoldSqlStatement(sql);
      try {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Rule " + executionCtx.getRuleId() + " --> " + sql);
        }
        if (index == translationResult.getRetSqlIndex()) {
          ret = metastore.executeFilesPathQuery(sql);
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

  public String genVirtualAccessCountTableTopValueOnStoragePolicy(List<Object> parameters) {
    genVirtualAccessCountTableValueOnStoragePolicy(parameters, true);
    return null;
  }

  public String genVirtualAccessCountTableBottomValueOnStoragePolicy(List<Object> parameters) {
    genVirtualAccessCountTableValueOnStoragePolicy(parameters, false);
    return null;
  }

  private void genVirtualAccessCountTableValueOnStoragePolicy(List<Object> parameters,
      boolean top) {
    List<Object> paraList = (List<Object>) parameters.get(0);
    String table = (String) parameters.get(1);
    String var = (String) parameters.get(2);
    Long num = (Long) paraList.get(1);
    String storage = ((String) paraList.get(2)).toUpperCase();
    String sqlsub;
    if (storage.equals("CACHE")) {
      sqlsub = String.format("SELECT %s.fid, %s.count FROM %s LEFT JOIN cached_file ON "
          + "(%s.fid = cached_file.fid)", table, table, table, table);
    } else {
      Integer id = null;
      try {
        id = metastore.getStoragePolicyID(storage);
      } catch (Exception e) {
        // Ignore
      }
      if (id == null) {
        id = -1; // safe return
      }
      sqlsub = String.format("SELECT %s.fid, %s.count FROM %s LEFT JOIN file ON "
          + "(%s.fid = file.fid) WHERE file.sid = %d",
          table, table, table, table, id);
    }

    String sql0 = String.format(
        "SELECT %s(count) FROM ( SELECT * FROM (%s) AS %s ORDER BY count %sLIMIT %d ) AS %s;",
        top ? "min" : "max",
        sqlsub,
        table + "_AL1_TMP",
        top ? "DESC " : "",
        num,
        table + "_AL2_TMP");
    Long count = null;
    try {
      count = metastore.queryForLong(sql0);
    } catch (MetaStoreException e) {
      LOG.error(String.format("Get %s access count on storage [%s] from table '%s' error [%s].",
          top ? "top" : "bottom", storage, table, sql0), e);
    }
    executionCtx.setProperty(var, count == null ? 0L : count);
  }

  public String genVirtualAccessCountTable(List<Object> parameters) {
    List<Object> paraList = (List<Object>) parameters.get(0);
    String newTable = (String) parameters.get(1);
    Long interval = (Long) paraList.get(0);
    String countFilter = "";
    List<String> tableNames = getAccessCountTablesDuringLast(interval);
    return generateSQL(tableNames, newTable, countFilter, metastore);
  }

  @VisibleForTesting
  static String generateSQL(
      List<String> tableNames, String newTable, String countFilter, MetaStore adapter) {
    String sqlFinal, sqlCreate;
    if (tableNames.size() <= 1) {
      String tableName = tableNames.isEmpty() ? "blank_access_count_info" : tableNames.get(0);
      sqlCreate = "CREATE TABLE " + newTable + "(fid INTEGER NOT NULL, count INTEGER NOT NULL);";
      try {
        adapter.execute(sqlCreate);
      } catch (MetaStoreException e) {
        LOG.error("Cannot create table " + newTable, e);
      }
      sqlFinal = "INSERT INTO " + newTable + " SELECT * FROM " + tableName + ";";
    } else {
      String sqlPrefix = "SELECT fid, SUM(count) AS count FROM (\n";
      String sqlUnion = "SELECT fid, count FROM " + tableNames.get(0) + " \n";
      for (int i = 1; i < tableNames.size(); i++) {
        sqlUnion += "UNION ALL\n" + "SELECT fid, count FROM " + tableNames.get(i) + " \n";
      }
      String sqlSufix = ") as tmp GROUP BY fid ";
      String sqlCountFilter =
          (countFilter == null || countFilter.isEmpty())
              ? ""
              : "HAVING SUM(count) " + countFilter;
      String sqlRe = sqlPrefix + sqlUnion + sqlSufix + sqlCountFilter;
      sqlCreate = "CREATE TABLE " + newTable + "(fid INTEGER NOT NULL, count INTEGER NOT NULL);";
      try {
        adapter.execute(sqlCreate);
      } catch (MetaStoreException e) {
        LOG.error("Cannot create table " + newTable, e);
      }
      sqlFinal = "INSERT INTO " + newTable + " SELECT * FROM (" + sqlRe + ") temp;";
    }
    return sqlFinal;
  }

  private List<String> getAccessCountTablesDuringLast(long lastInterval) {
    List<String> tableNames = new ArrayList<>();
    if (ruleManager == null || ruleManager.getStatesManager() == null) {
      return tableNames;
    }

    List<AccessCountTable> accTables = null;
    try {
      accTables = ruleManager.getStatesManager().getTablesInLast(lastInterval);
    } catch (MetaStoreException e) {
      LOG.error("Rule " + executionCtx.getRuleId() + " get access info tables exception", e);
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Rule " + executionCtx.getRuleId() + " got " + accTables.size() + " tables:");
      int idx = 1;
      for (AccessCountTable t : accTables) {
        LOG.debug(
            idx + ".  " + (t.isEphemeral() ? " [TABLE] " : "        ") + t.getTableName() + " ");
      }
    }

    if (accTables == null || accTables.isEmpty()) {
      return tableNames;
    }

    for (AccessCountTable t : accTables) {
      tableNames.add(t.getTableName());
      if (t.isEphemeral()) {
        dynamicCleanups.push("DROP TABLE IF EXISTS " + t.getTableName() + ";");
      }
    }
    return tableNames;
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

    List<RuleExecutorPlugin> plugins = RuleExecutorPluginManager.getPlugins();

    long rid = executionCtx.getRuleId();
    try {
      if (ruleManager.isClosed()) {
        exitSchedule();
      }

      long endCheckTime;
      int numCmdSubmitted = 0;
      List<String> files = new ArrayList<>();

      RuleInfo info = ruleManager.getRuleInfo(rid);

      boolean continueExecution = true;
      for (RuleExecutorPlugin plugin : plugins) {
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
        files = executeFileRuleQuery();
        if (exited) {
          exitSchedule();
        }
      }
      endCheckTime = System.currentTimeMillis();
      if (continueExecution) {
        for (RuleExecutorPlugin plugin : plugins) {
          files = plugin.preSubmitCmdlet(info, files);
        }
        numCmdSubmitted = submitCmdlets(info, files);
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

  private int submitCmdlets(RuleInfo ruleInfo, List<String> files) {
    long ruleId = ruleInfo.getId();
    if (files == null || files.isEmpty() || ruleManager.getCmdletManager() == null) {
      return 0;
    }
    int nSubmitted = 0;
    List<RuleExecutorPlugin> plugins = RuleExecutorPluginManager.getPlugins();
    String template = translationResult.getCmdDescriptor().toCmdletString();
    for (String file : files) {
      if (exited) {
        break;
      }
      try {
        CmdletDescriptor cmd = new CmdletDescriptor(template, ruleId);
        cmd.setCmdletParameter(CmdletDescriptor.HDFS_FILE_PATH, file);
        for (RuleExecutorPlugin plugin : plugins) {
          cmd = plugin.preSubmitCmdletDescriptor(ruleInfo, translationResult, cmd);
        }
        long cid = ruleManager.getCmdletManager().submitCmdlet(cmd);
        // Not really submitted if cid is -1.
        if (cid != -1) {
          nSubmitted++;
        }
      } catch (QueueFullException e) {
        break;
      } catch (IOException e) {
        // it's common here, ignore this and continue submit
        LOG.debug("Failed to submit cmdlet for file {} due to IOException", file, e);
      } catch (ParseException e) {
        LOG.error("Failed to submit cmdlet for file: {}", file, e);
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

  public long getExitTime() {
    return exitTime;
  }
}
