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
package org.smartdata.metastore.dao.postgres;

import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.ReplicationPolicyDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.ReplicationPolicySortField;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.PreserveAttribute;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationPoliciesInfo;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationPolicyStatus;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationScheduleType;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;
import org.smartdata.model.request.ReplicationPolicySearchRequest;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.metastore.queries.MetastoreQuery.select;
import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.column.MetastoreQueryColumnDsl.countAll;
import static org.smartdata.metastore.queries.column.MetastoreQueryColumnDsl.countFiltered;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.inStrings;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.likeCaseInsensitive;

/**
 * Stores policies in a single table with tags and source entities as array columns.
 */
public class PostgresReplicationPolicyDao extends SearchableAbstractDao<
    ReplicationPolicySearchRequest, ReplicationPolicyInfo, ReplicationPolicySortField>
    implements ReplicationPolicyDao {

  private static final String TABLE_NAME = "replication_policy";

  private static final String ID_FIELD = "id";
  private static final String NAME_FIELD = "name";
  private static final String DESCRIPTION_FIELD = "description";
  private static final String STATUS_FIELD = "status";
  private static final String TARGET_CLUSTER_ID_FIELD = "target_cluster_id";
  private static final String TAGS_FIELD = "tags";
  private static final String DATABASES_FIELD = "databases";
  // tables are stored in the "db.table" format, since dots are not allowed in Hive names
  private static final String TABLES_FIELD = "tables";
  private static final String TABLE_NAME_REGEX_FIELD = "table_name_regex";
  private static final String DATA_ENABLED_FIELD = "data_replication_enabled";
  private static final String DATA_PRESERVED_ATTRIBUTES_FIELD = "data_preserved_attributes";
  private static final String DATA_EVENTS_FIELD = "data_events";
  private static final String METADATA_ENABLED_FIELD = "metadata_replication_enabled";
  private static final String METADATA_EVENTS_FIELD = "metadata_events";
  private static final String METADATA_CASCADE_FIELD = "metadata_cascade";
  private static final String SCHEDULE_TYPE_FIELD = "schedule_type";
  private static final String SCHEDULE_INTERVAL_FIELD = "schedule_interval";
  private static final String SCHEDULE_START_TIME_FIELD = "schedule_start_time";
  private static final String SCHEDULE_END_TIME_FIELD = "schedule_end_time";
  private static final String CREATE_TIME_FIELD = "create_time";
  private static final String UPDATE_TIME_FIELD = "update_time";

  private static final String TOTAL_POLICIES_COUNT_COLUMN = "total_policies_count";
  private static final String ACTIVE_POLICIES_COUNT_COLUMN = "active_policies_count";

  private static final String ENUMS_DELIMITER = ",";

  public PostgresReplicationPolicyDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
  }

  @Override
  public Optional<ReplicationPolicyInfo> getById(long id) {
    return executeSingle(
        selectAll()
            .from(TABLE_NAME)
            .where(
                equal(ID_FIELD, id)
            )
    );
  }

  @Override
  public long insert(ReplicationPolicyInfo policy) {
    return simpleJdbcInsert()
        .usingGeneratedKeyColumns(ID_FIELD)
        .executeAndReturnKey(toMap(policy))
        .longValue();
  }

  @Override
  public boolean update(ReplicationPolicyInfo policy) {
    Map<String, Object> properties = toMap(policy);
    properties.remove(CREATE_TIME_FIELD);
    return updateIncludingNulls(properties, ID_FIELD + " = ?", policy.getId()) > 0;
  }

  @Override
  public List<String> getTags() {
    return jdbcTemplate.queryForList("SELECT DISTINCT tag"
        + " FROM " + TABLE_NAME + ", UNNEST(" + TAGS_FIELD + ") AS tag"
        + " ORDER BY tag", String.class);
  }

  @Override
  public ReplicationPoliciesInfo getPoliciesInfo() {
    MetastoreQuery query = select(
        countAll(TOTAL_POLICIES_COUNT_COLUMN),
        countFiltered(ACTIVE_POLICIES_COUNT_COLUMN,
            equal(STATUS_FIELD, ReplicationPolicyStatus.ACTIVE.name()))
    ).from(TABLE_NAME);

    return executeSingle(query, this::mapPoliciesInfoRow)
        .orElse(new ReplicationPoliciesInfo(0L, 0L));
  }

  @Override
  protected MetastoreQuery searchQuery(ReplicationPolicySearchRequest searchRequest) {
    return selectAll()
        .from(TABLE_NAME)
        .where(
            likeCaseInsensitive(NAME_FIELD, searchRequest.getNameLike()),
            inStrings(STATUS_FIELD, searchRequest.getStatuses()),
            in(TARGET_CLUSTER_ID_FIELD, searchRequest.getTargetClusterIds())
        );
  }

  @Override
  protected ReplicationPolicyInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return ReplicationPolicyInfo.builder()
        .id(resultSet.getLong(ID_FIELD))
        .name(resultSet.getString(NAME_FIELD))
        .description(resultSet.getString(DESCRIPTION_FIELD))
        .status(ReplicationPolicyStatus.valueOf(resultSet.getString(STATUS_FIELD)))
        .tags(getStrings(resultSet, TAGS_FIELD))
        .source(mapSource(resultSet))
        .targetClusterId(resultSet.getLong(TARGET_CLUSTER_ID_FIELD))
        .dataReplication(mapDataReplication(resultSet))
        .metadataReplication(mapMetadataReplication(resultSet))
        .schedule(mapSchedule(resultSet))
        .createTime(Instant.ofEpochMilli(resultSet.getLong(CREATE_TIME_FIELD)))
        .updateTime(Instant.ofEpochMilli(resultSet.getLong(UPDATE_TIME_FIELD)))
        .build();
  }

  private ReplicationSource mapSource(ResultSet resultSet) throws SQLException {
    return ReplicationSource.builder()
        .databases(getStrings(resultSet, DATABASES_FIELD))
        .tables(Optional.ofNullable(getStrings(resultSet, TABLES_FIELD))
            .map(tables -> tables.stream()
                .map(PostgresReplicationPolicyDao::parseSourceTable)
                .collect(Collectors.toList()))
            .orElse(null))
        .tableNameRegex(resultSet.getString(TABLE_NAME_REGEX_FIELD))
        .build();
  }

  private DataReplicationSettings mapDataReplication(ResultSet resultSet) throws SQLException {
    return DataReplicationSettings.builder()
        .enabled(resultSet.getBoolean(DATA_ENABLED_FIELD))
        .preservedAttributes(parseEnums(PreserveAttribute.class,
            resultSet.getString(DATA_PRESERVED_ATTRIBUTES_FIELD)))
        .events(parseEnums(FileDiffType.class,
            resultSet.getString(DATA_EVENTS_FIELD)))
        .build();
  }

  private MetadataReplicationSettings mapMetadataReplication(ResultSet resultSet)
      throws SQLException {
    return MetadataReplicationSettings.builder()
        .enabled(resultSet.getBoolean(METADATA_ENABLED_FIELD))
        .events(parseEnums(HiveOperation.class,
            resultSet.getString(METADATA_EVENTS_FIELD)))
        .cascade(resultSet.getBoolean(METADATA_CASCADE_FIELD))
        .build();
  }

  private ReplicationSchedule mapSchedule(ResultSet resultSet) throws SQLException {
    return ReplicationSchedule.builder()
        .type(ReplicationScheduleType.valueOf(resultSet.getString(SCHEDULE_TYPE_FIELD)))
        .intervalSeconds(getNullableLong(resultSet, SCHEDULE_INTERVAL_FIELD))
        .startTime(toInstant(getNullableLong(resultSet, SCHEDULE_START_TIME_FIELD)))
        .endTime(toInstant(getNullableLong(resultSet, SCHEDULE_END_TIME_FIELD)))
        .build();
  }

  private static List<String> getStrings(ResultSet resultSet, String column) throws SQLException {
    Array array = resultSet.getArray(column);
    return array == null ? null : Arrays.asList((String[]) array.getArray());
  }

  private static String[] toArray(List<String> values) {
    return values == null ? null : values.toArray(new String[0]);
  }

  private static SourceTable parseSourceTable(String fullTableName) {
    int separatorIndex = fullTableName.indexOf('.');
    return SourceTable.of(
        fullTableName.substring(0, separatorIndex),
        fullTableName.substring(separatorIndex + 1));
  }

  private Map<String, Object> toMap(ReplicationPolicyInfo policy) {
    DataReplicationSettings dataReplication = policy.getDataReplication();
    MetadataReplicationSettings metadataReplication = policy.getMetadataReplication();

    Map<String, Object> parameters = new HashMap<>();
    parameters.put(NAME_FIELD, policy.getName());
    parameters.put(DESCRIPTION_FIELD, policy.getDescription());
    parameters.put(STATUS_FIELD, policy.getStatus().name());
    parameters.put(TARGET_CLUSTER_ID_FIELD, policy.getTargetClusterId());
    parameters.put(TAGS_FIELD, toArray(policy.getTags()));
    parameters.put(DATABASES_FIELD, toArray(policy.getSource().getDatabases()));
    parameters.put(TABLES_FIELD, Optional.ofNullable(policy.getSource().getTables())
        .map(tables -> tables.stream()
            .map(table -> table.getDbName() + "." + table.getName())
            .toArray(String[]::new))
        .orElse(null));
    parameters.put(TABLE_NAME_REGEX_FIELD, policy.getSource().getTableNameRegex());

    parameters.put(DATA_ENABLED_FIELD, dataReplication.isEnabled());
    parameters.put(DATA_PRESERVED_ATTRIBUTES_FIELD,
        serializeEnums(dataReplication.getPreservedAttributes()));
    parameters.put(DATA_EVENTS_FIELD, serializeEnums(dataReplication.getEvents()));

    parameters.put(METADATA_ENABLED_FIELD, metadataReplication.isEnabled());
    parameters.put(METADATA_EVENTS_FIELD, serializeEnums(metadataReplication.getEvents()));
    parameters.put(METADATA_CASCADE_FIELD, metadataReplication.isCascade());

    ReplicationSchedule schedule = policy.getSchedule();
    parameters.put(SCHEDULE_TYPE_FIELD, schedule.getType().name());
    parameters.put(SCHEDULE_INTERVAL_FIELD, schedule.getIntervalSeconds());
    parameters.put(SCHEDULE_START_TIME_FIELD, toEpochMilli(schedule.getStartTime()));
    parameters.put(SCHEDULE_END_TIME_FIELD, toEpochMilli(schedule.getEndTime()));

    parameters.put(CREATE_TIME_FIELD, policy.getCreateTime().toEpochMilli());
    parameters.put(UPDATE_TIME_FIELD, policy.getUpdateTime().toEpochMilli());
    return parameters;
  }

  private ReplicationPoliciesInfo mapPoliciesInfoRow(
      ResultSet resultSet, int rowNum) throws SQLException {
    return new ReplicationPoliciesInfo(
        resultSet.getLong(TOTAL_POLICIES_COUNT_COLUMN),
        resultSet.getLong(ACTIVE_POLICIES_COUNT_COLUMN));
  }

  private static <EnumT extends Enum<EnumT>> String serializeEnums(Set<EnumT> values) {
    if (values == null) {
      return null;
    }
    return values.stream()
        .sorted()
        .map(Enum::name)
        .collect(Collectors.joining(ENUMS_DELIMITER));
  }

  private static <EnumT extends Enum<EnumT>> Set<EnumT> parseEnums(
      Class<EnumT> enumClass, String rawValues) {
    if (rawValues == null) {
      return null;
    }
    Set<EnumT> values = EnumSet.noneOf(enumClass);
    if (rawValues.isEmpty()) {
      return values;
    }
    for (String value : rawValues.split(ENUMS_DELIMITER)) {
      values.add(Enum.valueOf(enumClass, value));
    }
    return values;
  }

  private static Long getNullableLong(ResultSet resultSet, String field) throws SQLException {
    long value = resultSet.getLong(field);
    return resultSet.wasNull() ? null : value;
  }

  private static Instant toInstant(Long epochMilli) {
    return epochMilli == null ? null : Instant.ofEpochMilli(epochMilli);
  }

  private static Long toEpochMilli(Instant instant) {
    return instant == null ? null : instant.toEpochMilli();
  }
}
