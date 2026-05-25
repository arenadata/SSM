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

import com.hazelcast.internal.util.CollectionUtil;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
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
import org.smartdata.utils.PathUtil;
import org.smartdata.utils.StringUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.utils.PathUtil.addPathSeparator;
import static org.smartdata.utils.StringUtil.ssmPatternsToRegex;

public class FileCopyDrPlugin implements RuleExecutorPlugin {
  private static final Logger LOG =
      LoggerFactory.getLogger(FileCopyDrPlugin.class.getName());

  private static final String ALL_FILES_PATTERN = "/*";
  private static final String PATTERN_BASE_DIRS_DELIMITER = ",";

  private final MetaStore metaStore;
  private final FileCopyScheduleStrategy copyScheduleStrategy;

  public FileCopyDrPlugin(MetaStore metaStore, FileCopyScheduleStrategy copyScheduleStrategy) {
    this.metaStore = metaStore;
    this.copyScheduleStrategy = copyScheduleStrategy;
  }

  public void onNewRuleExecutor(RuleInfo ruleInfo, RuleTranslationResult translationResult) {
    long ruleId = ruleInfo.getId();
    List<String> pathPatterns = getPathPatterns(translationResult);

    CmdletDescriptor cmdletDescriptor = translationResult.getCmdDescriptor();
    for (int i = 0; i < cmdletDescriptor.getActionSize(); i++) {
      if (cmdletDescriptor.getActionName(i).equals(SyncAction.NAME)) {
        String rawPreserveArg = cmdletDescriptor.getActionArgs(i)
            .get(SyncAction.PRESERVE);
        // fail fast if preserve arg is not valid
        validatePreserveArg(rawPreserveArg);

        wrapGetFilesToCopyQuery(translationResult, pathPatterns);

        Map<String, String> actionArgs = cmdletDescriptor.getActionArgs(i);
        String destActionArg = actionArgs.get(SyncAction.DEST);
        String dest = addPathSeparator(destActionArg);
        cmdletDescriptor.addActionArg(i, SyncAction.DEST, dest);

        Set<FileDiffType> includedDiffTypes = parseIncludedDiffTypes(actionArgs);
        BackUpInfo backUpInfo = buildBackupInfo(ruleId, dest, translationResult, pathPatterns, includedDiffTypes);

        cmdletDescriptor.addActionArg(i, SyncAction.SRC, backUpInfo.getSrc());

        storeBackupInfo(ruleId, backUpInfo);

        LOG.debug("Rule executor added for sync rule {} src={}  dest={}",
            ruleInfo, backUpInfo.getSrc(), dest);
        break;
      }
    }
  }

  public boolean preExecution(final RuleInfo ruleInfo, RuleTranslationResult tResult) {
    return true;
  }

  public List<String> preSubmitCmdlet(final RuleInfo ruleInfo, List<String> objects) {
    return objects;
  }

  public CmdletDescriptor preSubmitCmdletDescriptor(
      RuleInfo ruleInfo, RuleTranslationResult tResult, CmdletDescriptor descriptor) {
    return descriptor;
  }

  public void onRuleExecutorExit(RuleInfo ruleInfo) {
    long ruleId = ruleInfo.getId();
    try {
      metaStore.deleteBackUpInfo(ruleId);
    } catch (MetaStoreException e) {
      LOG.error("Error removing backup info for rule {}", ruleInfo.getId(), e);
    }
  }

  private void storeBackupInfo(long ruleId, BackUpInfo backUpInfo) {
    try {
      metaStore.deleteBackUpInfo(ruleId);

      if (backUpInfo.getIncludedFileDiffTypes().contains(FileDiffType.BASESYNC)) {
        storeBaseSync(backUpInfo);
      }

      metaStore.insertBackUpInfo(backUpInfo);
    } catch (MetaStoreException exc) {
      LOG.error("Error inserting backup info {}", backUpInfo, exc);
    }
  }

  private void storeBaseSync(BackUpInfo backUpInfo) throws MetaStoreException {
    FileDiff fileDiff = new FileDiff(FileDiffType.BASESYNC);
    fileDiff.setSrc(backUpInfo.getSrc());
    fileDiff.getParameters().put(SyncAction.DEST, backUpInfo.getDest());
    metaStore.insertFileDiff(fileDiff);
  }

  private void wrapGetFilesToCopyQuery(
      RuleTranslationResult tResult, List<String> pathsCheckGlob) {
    List<String> statements = tResult.getSqlStatements();
    String oldFetchFilesQuery = statements.get(statements.size() - 1)
        .replace(";", "");
    String wrappedQuery = copyScheduleStrategy
        .wrapGetFilesToCopyQuery(oldFetchFilesQuery, pathsCheckGlob);
    statements.set(statements.size() - 1, wrappedQuery);

    LOG.info("Transformed '{}' rule's fetch files sql from '{}' to '{}'",
        tResult.getCmdDescriptor().getCmdletString(), oldFetchFilesQuery, wrappedQuery);
  }

  private List<String> getPathPatternBaseDirs(List<String> paths) {
    return paths.stream()
        .map(PathUtil::getBaseDir)
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

  private BackUpInfo buildBackupInfo(
      long ruleId, String dest, RuleTranslationResult tResult,
      List<String> pathPatterns, Set<FileDiffType> includedDiffTypes) {
    String patternBaseDirs = StringUtil.join(
        PATTERN_BASE_DIRS_DELIMITER,
        getPathPatternBaseDirs(pathPatterns));

    return BackUpInfo.builder()
        .rid(ruleId)
        .src(patternBaseDirs)
        .srcPattern(ssmPatternsToRegex(pathPatterns))
        .dest(dest)
        .period(tResult.getScheduleInfo().getMinimalEvery())
        .includedFileDiffTypes(includedDiffTypes)
        .build();
  }

  private Set<FileDiffType> parseIncludedDiffTypes(Map<String, String> actionArgs) {
    Set<FileDiffType> includedDiffTypes = parseDiffTypes(actionArgs.get(SyncAction.INCLUDE));
    if (CollectionUtil.isNotEmpty(includedDiffTypes)) {
      return includedDiffTypes;
    }

    Set<FileDiffType> allowedOperations = new HashSet<>(
        Arrays.asList(FileDiffType.values())
    );
    Set<FileDiffType> excludedDiffTypes = parseDiffTypes(actionArgs.get(SyncAction.EXCLUDE));
    allowedOperations.removeAll(excludedDiffTypes);
    return allowedOperations;
  }

  private Set<FileDiffType> parseDiffTypes(String rawDiffTypes) {
    if (rawDiffTypes == null) {
      return Collections.emptySet();
    }

    return Arrays.stream(rawDiffTypes.split(","))
        .map(String::toUpperCase)
        .map(diffType -> EnumUtils.getEnum(FileDiffType.class, diffType.trim()))
        .filter(Objects::nonNull)
        .map(FileDiffType::expandFilterableType)
        .flatMap(Set::stream)
        .collect(Collectors.toSet());
  }

  private void validatePreserveArg(String rawPreserveArg) {
    if (StringUtils.isBlank(rawPreserveArg)) {
      return;
    }

    for (String attribute : rawPreserveArg.split(",")) {
      CopyFileAction.validatePreserveArg(attribute);
    }
  }

  private List<String> getPathPatterns(RuleTranslationResult translationResult) {
    List<String> pathPatterns = translationResult.getPathPatterns();
    return pathPatterns.isEmpty()
        ? Collections.singletonList(ALL_FILES_PATTERN)
        : pathPatterns;
  }
}
