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
package org.smartdata.server.engine.rule.copy;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.action.SyncAction;
import org.smartdata.hdfs.action.CopyFileAction;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.BackUpInfo;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.utils.StringUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.smartdata.utils.StringUtil.ssmPatternsToRegex;

public class FileCopyDrPlugin implements RuleExecutorPlugin {
  private final MetaStore metaStore;
  private final FileCopyScheduleStrategy copyScheduleStrategy;
  private final Map<Long, List<BackUpInfo>> backups = new HashMap<>();
  private static final Logger LOG =
      LoggerFactory.getLogger(FileCopyDrPlugin.class.getName());

  public FileCopyDrPlugin(MetaStore metaStore, FileCopyScheduleStrategy copyScheduleStrategy) {
    this.metaStore = metaStore;
    this.copyScheduleStrategy = copyScheduleStrategy;
  }

  public void onNewRuleExecutor(final RuleInfo ruleInfo, RuleTranslationResult tResult) {
    long ruleId = ruleInfo.getId();
    List<String> pathsCheckGlob = tResult.getGlobPathCheck();
    if (pathsCheckGlob.isEmpty()) {
      pathsCheckGlob = Collections.singletonList("/*");
    }
    List<String> pathsCheck = getPathMatchesList(pathsCheckGlob);

    String dirs = StringUtil.join(",", pathsCheck);
    CmdletDescriptor des = tResult.getCmdDescriptor();
    for (int i = 0; i < des.getActionSize(); i++) {
      if (des.getActionName(i).equals(SyncAction.NAME)) {
        String rawPreserveArg = des.getActionArgs(i).get(SyncAction.PRESERVE);
        // fail fast if preserve arg is not valid
        validatePreserveArg(rawPreserveArg);

        List<String> statements = tResult.getSqlStatements();

        String oldFetchFilesQuery = statements.get(statements.size() - 1)
            .replace(";", "");
        String wrappedQuery = copyScheduleStrategy
            .wrapGetFilesToCopyQuery(oldFetchFilesQuery, pathsCheckGlob);
        statements.set(statements.size() - 1, wrappedQuery);

        LOG.info("Transformed '{}' rule's fetch files sql from '{}' to '{}'",
            ruleInfo.getRuleText(), oldFetchFilesQuery, wrappedQuery);

        BackUpInfo backUpInfo = new BackUpInfo();
        backUpInfo.setRid(ruleId);
        backUpInfo.setSrc(dirs);
        backUpInfo.setSrcPattern(ssmPatternsToRegex(pathsCheckGlob));
        String dest = des.getActionArgs(i).get(SyncAction.DEST);
        if (!dest.endsWith("/")) {
          dest += "/";
          des.addActionArg(i, SyncAction.DEST, dest);
        }
        backUpInfo.setDest(dest);
        backUpInfo.setPeriod(tResult.getScheduleInfo().getMinimalEvery());

        des.addActionArg(i, SyncAction.SRC, dirs);

        LOG.debug("Rule executor added for sync rule {} src={}  dest={}", ruleInfo, dirs, dest);

        synchronized (backups) {
          if (!backups.containsKey(ruleId)) {
            backups.put(ruleId, new LinkedList<>());
          }
        }

        List<BackUpInfo> infos = backups.get(ruleId);
        synchronized (infos) {
          try {
            metaStore.deleteBackUpInfo(ruleId);
            // Add base Sync tag
            FileDiff fileDiff = new FileDiff(FileDiffType.BASESYNC);
            fileDiff.setSrc(backUpInfo.getSrc());
            fileDiff.getParameters().put("-dest", backUpInfo.getDest());
            metaStore.insertFileDiff(fileDiff);
            metaStore.insertBackUpInfo(backUpInfo);
            infos.add(backUpInfo);
          } catch (MetaStoreException e) {
            LOG.error("Insert backup info error:" + backUpInfo, e);
          }
        }
        break;
      }
    }
  }

  private List<String> getPathMatchesList(List<String> paths) {
    List<String> ret = new ArrayList<>();
    for (String p : paths) {
      String dir = StringUtil.getBaseDir(p);
      if (dir == null) {
        continue;
      }
      ret.add(dir);
    }
    return ret;
  }

  public boolean preExecution(final RuleInfo ruleInfo, RuleTranslationResult tResult) {
    return true;
  }

  public List<String> preSubmitCmdlet(final RuleInfo ruleInfo, List<String> objects) {
    return objects;
  }

  public CmdletDescriptor preSubmitCmdletDescriptor(
      final RuleInfo ruleInfo, RuleTranslationResult tResult, CmdletDescriptor descriptor) {
    return descriptor;
  }

  public void onRuleExecutorExit(final RuleInfo ruleInfo) {
    long ruleId = ruleInfo.getId();
    List<BackUpInfo> infos = backups.get(ruleId);
    if (infos == null) {
      return;
    }
    synchronized (infos) {
      try {
        if (infos.size() != 0) {
          infos.remove(0);
        }

        if (infos.size() == 0) {
          backups.remove(ruleId);
          metaStore.deleteBackUpInfo(ruleId);
        }
      } catch (MetaStoreException e) {
        LOG.error("Remove backup info error:" + ruleInfo, e);
      }
    }
  }

  private void validatePreserveArg(String rawPreserveArg) {
    if (StringUtils.isBlank(rawPreserveArg)) {
      return;
    }

    for (String attribute: rawPreserveArg.split(",")) {
      CopyFileAction.validatePreserveArg(attribute);
    }
  }
}
