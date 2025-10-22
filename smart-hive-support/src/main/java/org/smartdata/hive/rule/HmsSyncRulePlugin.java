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
package org.smartdata.hive.rule;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.hive.action.HmsSyncAction;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.rule.RuleExecutorPlugin;
import org.smartdata.model.rule.RuleTranslationResult;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class HmsSyncRulePlugin implements RuleExecutorPlugin {

  private static final long START_FETCH_ID = -1L;

  private final HmsSyncProgressDao hmsSyncProgressDao;
  private final HmsEntityQueryWrapper hmsEntityQueryWrapper;

  public HmsSyncRulePlugin(HmsSyncProgressDao hmsSyncProgressDao) {
    this(hmsSyncProgressDao, HmsEntityQueryWrapper.withRuleProgressFiltering());
  }

  @Override
  public void onNewRuleExecutor(RuleInfo ruleInfo, RuleTranslationResult translationResult) {
    long ruleId = ruleInfo.getId();
    CmdletDescriptor cmdletDescriptor = translationResult.getCmdDescriptor();

    for (int i = 0; i < cmdletDescriptor.getActionSize(); i++) {
      if (cmdletDescriptor.getActionName(i).equals(HmsSyncAction.NAME)) {
        wrapGetEntitiesToSyncQuery(translationResult, ruleId);
        hmsSyncProgressDao.insertIfNotPresent(ruleId, START_FETCH_ID);

        break;
      }
    }
  }

  @Override
  public void onRuleExecutorExit(RuleInfo ruleInfo) {

  }

  @Override
  public List<String> preSubmitCmdlet(RuleInfo ruleInfo, List<String> objects) {
    return objects;
  }

  @Override
  public CmdletDescriptor preSubmitCmdletDescriptor(RuleInfo ruleInfo, RuleTranslationResult tResult,
      CmdletDescriptor descriptor) {
    return descriptor;
  }

  @Override
  public boolean preExecution(RuleInfo ruleInfo, RuleTranslationResult tResult) {
    return true;
  }

  private void wrapGetEntitiesToSyncQuery(RuleTranslationResult tResult, long ruleId) {
    List<String> statements = tResult.getSqlStatements();
    String oldFetchFilesQuery = statements.get(statements.size() - 1)
        .replace(";", "");
    String wrappedQuery = hmsEntityQueryWrapper.wrap(oldFetchFilesQuery, ruleId);
    statements.set(statements.size() - 1, wrappedQuery);

    log.info("Transformed '{}' rule's fetch HMS entities sql from '{}' to '{}'",
        tResult.getCmdDescriptor().getCmdletString(), oldFetchFilesQuery, wrappedQuery);
  }

}
