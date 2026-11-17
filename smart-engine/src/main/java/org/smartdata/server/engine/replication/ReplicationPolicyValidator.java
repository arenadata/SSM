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
package org.smartdata.server.engine.replication;

import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.exception.NotFoundException;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.server.engine.ClusterManager;
import org.smartdata.server.engine.HiveCatalogManager;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Validates and normalizes the replication policy settings. Omitted optional settings
 * are kept as is, their default values are applied on the rules generation.
 */
class ReplicationPolicyValidator {
  private static final Comparator<SourceTable> SOURCE_TABLE_COMPARATOR =
      Comparator.comparing(SourceTable::getDbName)
          .thenComparing(SourceTable::getName);

  private final ClusterManager clusterManager;
  private final HiveCatalogManager hiveCatalogManager;

  ReplicationPolicyValidator(
      ClusterManager clusterManager, HiveCatalogManager hiveCatalogManager) {
    this.clusterManager = clusterManager;
    this.hiveCatalogManager = hiveCatalogManager;
  }

  /**
   * Validates and normalizes the policy settings: name, description, tags, source,
   * target cluster, replication settings and schedule.
   *
   * @return the target policy with the validated settings applied
   */
  public ReplicationPolicyInfo validate(
      ReplicationPolicyInfo target, ReplicationPolicyInfo settings) throws IOException {
    String name = StringUtils.trimToNull(settings.getName());
    if (name == null) {
      throw new IllegalArgumentException("Policy name can't be empty");
    }

    ClusterInfo targetCluster = validateTargetCluster(settings.getTargetClusterId());
    DataReplicationSettings dataReplication =
        validateDataReplication(settings.getDataReplication());
    MetadataReplicationSettings metadataReplication =
        validateMetadataReplication(settings.getMetadataReplication(), targetCluster);
    if (!dataReplication.isEnabled() && !metadataReplication.isEnabled()) {
      throw new IllegalArgumentException(
          "Either data or metadata replication should be enabled");
    }

    return target.toBuilder()
        .name(name)
        .description(StringUtils.trimToNull(settings.getDescription()))
        .tags(validateTags(settings.getTags()))
        .source(validateSource(settings.getSource()))
        .targetClusterId(targetCluster.getId())
        .dataReplication(dataReplication)
        .metadataReplication(metadataReplication)
        .schedule(validateSchedule(settings.getSchedule()))
        .build();
  }

  private List<String> validateTags(List<String> tags) {
    if (tags == null) {
      return null;
    }

    Set<String> validatedTags = new TreeSet<>();
    for (String tag : tags) {
      String trimmedTag = StringUtils.trimToNull(tag);
      if (trimmedTag == null) {
        throw new IllegalArgumentException("Policy tag can't be empty");
      }
      validatedTags.add(trimmedTag);
    }
    return new ArrayList<>(validatedTags);
  }

  private ReplicationSource validateSource(ReplicationSource source) throws IOException {
    if (source == null || source.getDatabases() == null || source.getDatabases().isEmpty()) {
      throw new IllegalArgumentException("At least one source database should be selected");
    }

    Set<String> databases = new TreeSet<>();
    for (String database : source.getDatabases()) {
      String dbName = StringUtils.trimToNull(database);
      if (dbName == null) {
        throw new IllegalArgumentException("Source database name can't be empty");
      }
      rejectIfNotFound(() -> hiveCatalogManager.getDatabase(dbName),
          "Source Hive database not found: " + dbName);
      databases.add(dbName);
    }

    List<SourceTable> tables = source.getTables() == null
        ? null
        : validateTables(source.getTables(), databases);

    String tableNameRegex = StringUtils.trimToNull(source.getTableNameRegex());
    if (tableNameRegex != null) {
      if (tables != null && !tables.isEmpty()) {
        throw new IllegalArgumentException(
            "Either exact source tables or the table name pattern should be specified");
      }
      // the glob pattern is used in the string literals of the rules, which can't be escaped
      if (tableNameRegex.contains("\"")) {
        throw new IllegalArgumentException(
            "Table name pattern can't contain quotes: " + tableNameRegex);
      }
    }

    return ReplicationSource.builder()
        .databases(new ArrayList<>(databases))
        .tables(tables)
        .tableNameRegex(tableNameRegex)
        .build();
  }

  private List<SourceTable> validateTables(List<SourceTable> sourceTables, Set<String> databases)
      throws IOException {
    Set<SourceTable> tables = new TreeSet<>(SOURCE_TABLE_COMPARATOR);
    for (SourceTable table : sourceTables) {
      SourceTable trimmedTable = SourceTable.of(
          StringUtils.trimToEmpty(table.getDbName()), StringUtils.trimToEmpty(table.getName()));
      if (!databases.contains(trimmedTable.getDbName())) {
        throw new IllegalArgumentException(
            "Source table should belong to one of the selected databases: " + table);
      }
      rejectIfNotFound(
          () -> hiveCatalogManager.getTable(trimmedTable.getDbName(), trimmedTable.getName()),
          "Source Hive table not found: " + table);
      tables.add(trimmedTable);
    }
    return new ArrayList<>(tables);
  }

  private ClusterInfo validateTargetCluster(Long clusterId) throws IOException {
    if (clusterId == null) {
      throw new IllegalArgumentException("Target cluster should be selected");
    }

    ClusterInfo cluster = rejectIfNotFound(() -> clusterManager.getCluster(clusterId),
        "Target cluster not found: " + clusterId);
    if (cluster.getStatus() == ClusterStatus.COMPLETED) {
      throw new IllegalArgumentException(
          "Completed cluster can't be the replication target: " + clusterId);
    }
    return cluster;
  }

  private DataReplicationSettings validateDataReplication(DataReplicationSettings settings) {
    if (settings == null) {
      throw new IllegalArgumentException("Data replication settings should be specified");
    }

    validateEvents(settings.getEvents(), FileDiffType.FILTERABLE_DIFF_TYPES, "data");

    return settings;
  }

  private MetadataReplicationSettings validateMetadataReplication(
      MetadataReplicationSettings settings, ClusterInfo targetCluster) {
    if (settings == null) {
      throw new IllegalArgumentException("Metadata replication settings should be specified");
    }
    if (settings.isEnabled() && targetCluster.getHiveThriftUri() == null) {
      throw new IllegalArgumentException(
          "Metadata can't be replicated to the cluster without Hive Thrift URI: "
              + targetCluster.getName());
    }

    validateEvents(settings.getEvents(), HiveOperation.FILTERABLE_OPERATIONS, "metadata");

    return settings;
  }

  /**
   * Validates that only the filterable events are selected.
   * Omitted or empty events mean all events, so they aren't validated.
   */
  private <EnumT extends Enum<EnumT>> void validateEvents(
      Set<EnumT> events, Set<EnumT> filterableEvents, String replicationType) {
    if (events != null && !filterableEvents.containsAll(events)) {
      throw new IllegalArgumentException("Unsupported " + replicationType
          + " replication events: " + Sets.difference(events, filterableEvents)
          + ". Supported events: " + filterableEvents);
    }
  }

  private ReplicationSchedule validateSchedule(ReplicationSchedule schedule) {
    if (schedule == null) {
      throw new IllegalArgumentException("Schedule should be specified");
    }
    if (schedule.getType() == null) {
      throw new IllegalArgumentException("Schedule type should be specified");
    }

    Long intervalSeconds = schedule.getIntervalSeconds();
    Instant startTime = schedule.getStartTime();
    Instant endTime = schedule.getEndTime();
    switch (schedule.getType()) {
      case EVENT_DRIVEN:
        if (intervalSeconds != null || startTime != null || endTime != null) {
          throw new IllegalArgumentException(
              "Event-driven schedule can't have the interval, start or end time");
        }
        break;
      case AT:
        if (intervalSeconds != null || endTime != null) {
          throw new IllegalArgumentException(
              "Single run schedule can't have the interval or end time");
        }
        break;
      case EVERY:
        if (intervalSeconds == null || intervalSeconds <= 0) {
          throw new IllegalArgumentException(
              "Periodic schedule should have the positive interval");
        }
        if (startTime != null && endTime != null && !startTime.isBefore(endTime)) {
          throw new IllegalArgumentException(
              "Start time of the periodic schedule should be before the end time");
        }
        break;
      default:
        throw new IllegalArgumentException("Unsupported schedule type: " + schedule.getType());
    }
    return schedule;
  }
  /**
   * Converts the absence of the referenced entity to the validation error.
   */
  private static <T> T rejectIfNotFound(EntityGetter<T> getter, String errorMessage)
      throws IOException {
    try {
      return getter.get();
    } catch (NotFoundException exception) {
      throw new IllegalArgumentException(errorMessage, exception);
    }
  }

  private interface EntityGetter<T> {
    T get() throws IOException;
  }
}
