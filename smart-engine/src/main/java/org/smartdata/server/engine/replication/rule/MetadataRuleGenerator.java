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

import org.apache.commons.collections4.CollectionUtils;
import org.smartdata.hive.action.HmsSyncAction;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.server.engine.replication.rule.dsl.OrCondition;
import org.smartdata.server.engine.replication.rule.dsl.RuleAction;
import org.smartdata.server.engine.replication.rule.dsl.RuleCondition;
import org.smartdata.server.engine.replication.rule.dsl.RuleObjectType;
import org.smartdata.server.engine.replication.rule.dsl.SsmRule;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.smartdata.server.engine.replication.rule.ReplicationRuleSupport.includedEvents;
import static org.smartdata.server.engine.replication.rule.ReplicationRuleSupport.toTrigger;
import static org.smartdata.server.engine.replication.rule.dsl.MatchesCondition.nameMatches;

/**
 * Generates an hms-sync rule per source database, replicating either the whole database,
 * its selected tables or the tables matching the table name glob pattern.
 */
public class MetadataRuleGenerator implements RuleGenerator<MetadataRuleGenerationRequest> {

  @Override
  public RuleGenerationResult generate(MetadataRuleGenerationRequest request) {
    validateRequest(request);

    MetadataReplicationSettings settings = request.getSettings();
    if (!settings.isEnabled()) {
      return RuleGenerationResult.empty();
    }

    List<GeneratedRule> rules = request.getSource().getDatabases().stream()
        .sorted()
        .map(dbName -> buildRule(request, dbName))
        .collect(Collectors.toList());
    return new RuleGenerationResult(rules);
  }

  private GeneratedRule buildRule(MetadataRuleGenerationRequest request, String dbName) {
    SsmRule rule = SsmRule.builder()
        .objectType(RuleObjectType.HMS)
        .trigger(toTrigger(request.getSchedule()))
        .condition(buildCondition(request.getSource(), dbName))
        .action(buildAction(request))
        .build();
    return new GeneratedRule(ReplicationRuleType.METADATA, dbName, rule);
  }

  private RuleCondition buildCondition(ReplicationSource source, String dbName) {
    Set<String> tables = selectedTables(source, dbName);
    if (tables.isEmpty()) {
      String tablePattern = Optional.ofNullable(source.getTableNameRegex()).orElse("*");
      return nameMatches(dbName + "." + tablePattern);
    }
    return new OrCondition(tables.stream()
        .map(table -> nameMatches(dbName + "." + table))
        .collect(Collectors.toList()));
  }

  private RuleAction buildAction(MetadataRuleGenerationRequest request) {
    ClusterInfo targetCluster = request.getTargetCluster();
    RuleAction action = RuleAction.action(HmsSyncAction.NAME)
        .arg(HmsSyncAction.DEST, targetCluster.getHiveThriftUri());

    MetadataReplicationSettings settings = request.getSettings();
    if (settings.isCascade()) {
      action.flag(HmsSyncAction.CASCADE);
    }

    String sourceNameservice = request.getSourceNameservice();
    String targetNameservice = targetCluster.getHdfsNameservice();
    if (!sourceNameservice.equals(targetNameservice)) {
      action.arg(HmsSyncAction.NAMESERVICE_RENAME, sourceNameservice + " " + targetNameservice);
    }

    includedEvents(settings.getEvents(), HiveOperation.FILTERABLE_OPERATIONS)
        .ifPresent(events -> action.arg(HmsSyncAction.INCLUDE, events));
    return action;
  }

  private Set<String> selectedTables(ReplicationSource source, String dbName) {
    return CollectionUtils.emptyIfNull(source.getTables()).stream()
        .filter(table -> table.getDbName().equals(dbName))
        .map(SourceTable::getName)
        .collect(Collectors.toCollection(TreeSet::new));
  }

  private void validateRequest(MetadataRuleGenerationRequest request) {
    ClusterInfo targetCluster = request.getTargetCluster();
    if (targetCluster.getHiveThriftUri() == null) {
      throw new IllegalArgumentException(
          "Metadata can't be replicated to the cluster without Hive Thrift URI: "
              + targetCluster.getName());
    }
    // nameservices are required to replace the source HDFS locations in the replicated metadata
    if (targetCluster.getHdfsNameservice() == null) {
      throw new IllegalArgumentException(
          "Metadata can't be replicated to the cluster without HDFS nameservice: "
              + targetCluster.getName());
    }
    if (request.getSourceNameservice() == null) {
      throw new IllegalArgumentException("Source HDFS nameservice should be specified");
    }
  }
}
