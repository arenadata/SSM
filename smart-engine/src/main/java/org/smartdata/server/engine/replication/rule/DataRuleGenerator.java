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
package org.smartdata.server.engine.replication.rule;

import org.apache.commons.lang3.Strings;
import org.smartdata.action.SyncAction;
import org.smartdata.hdfs.action.CopyPreservedAttributesSupport;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.PreserveAttribute;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.server.engine.replication.rule.dsl.RuleAction;
import org.smartdata.server.engine.replication.rule.dsl.RuleObjectType;
import org.smartdata.server.engine.replication.rule.dsl.SsmRule;
import org.smartdata.utils.PathUtil;

import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.server.engine.replication.rule.ReplicationRuleSupport.includedEvents;
import static org.smartdata.server.engine.replication.rule.ReplicationRuleSupport.toTrigger;
import static org.smartdata.server.engine.replication.rule.dsl.MatchesCondition.pathMatches;

/**
 * Generates a sync rule per root directory of the replication source,
 * merged from the locations of the selected Hive entities.
 */
public class DataRuleGenerator implements RuleGenerator<DataRuleGenerationRequest> {
  static final Set<PreserveAttribute> DEFAULT_PRESERVED_ATTRIBUTES =
      EnumSet.of(PreserveAttribute.OWNER, PreserveAttribute.GROUP, PreserveAttribute.PERMISSIONS);

  @Override
  public RuleGenerationResult generate(DataRuleGenerationRequest request) {
    DataReplicationSettings settings = request.getSettings();
    if (!settings.isEnabled()) {
      return RuleGenerationResult.empty();
    }

    List<GeneratedRule> rules = normalizeRoots(request.getRoots()).stream()
        .map(root -> buildRule(request, root))
        .collect(Collectors.toList());
    return new RuleGenerationResult(rules);
  }

  private GeneratedRule buildRule(DataRuleGenerationRequest request, String root) {
    SsmRule rule = SsmRule.builder()
        .objectType(RuleObjectType.FILE)
        .trigger(toTrigger(request.getSchedule()))
        .condition(pathMatches(root + "*"))
        .action(buildAction(request, root))
        .build();
    return new GeneratedRule(ReplicationRuleType.DATA, root, rule);
  }

  /**
   * Normalizes the roots.
   *
   * @return sorted roots, ending with the path separator
   */
  private static List<String> normalizeRoots(List<String> roots) {
    return roots.stream()
        .map(PathUtil::addPathSeparator)
        .sorted()
        .distinct()
        .collect(Collectors.toList());
  }

  private RuleAction buildAction(DataRuleGenerationRequest request, String root) {
    String targetHdfsUri = Strings.CI.removeEnd(request.getTargetCluster().getHdfsUri(), "/");
    RuleAction action = RuleAction.action(SyncAction.NAME)
        .arg(SyncAction.DEST, targetHdfsUri + root)
        .arg(SyncAction.PRESERVE, renderPreservedAttributes(request.getSettings()));

    includedEvents(request.getSettings().getEvents(), FileDiffType.FILTERABLE_DIFF_TYPES)
        .ifPresent(events -> action.arg(SyncAction.INCLUDE, events));
    return action;
  }

  private static String renderPreservedAttributes(DataReplicationSettings settings) {
    Set<PreserveAttribute> attributes = Optional.ofNullable(settings.getPreservedAttributes())
        .orElse(DEFAULT_PRESERVED_ATTRIBUTES);
    if (attributes.isEmpty()) {
      return CopyPreservedAttributesSupport.PRESERVE_NONE;
    }
    // attributes are always specified explicitly, since the default attributes
    // of the copy and metadata sync actions are different
    return attributes.stream()
        .sorted()
        .map(PreserveAttribute::toString)
        .collect(Collectors.joining(","));
  }
}
