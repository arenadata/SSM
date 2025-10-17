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
package org.smartdata.hive;

import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.api.FunctionType;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.SQLCheckConstraint;
import org.apache.hadoop.hive.metastore.api.SQLDefaultConstraint;
import org.apache.hadoop.hive.metastore.api.SQLForeignKey;
import org.apache.hadoop.hive.metastore.api.SQLNotNullConstraint;
import org.apache.hadoop.hive.metastore.api.SQLPrimaryKey;
import org.apache.hadoop.hive.metastore.api.SQLUniqueConstraint;
import org.apache.hadoop.hive.metastore.api.StorageDescriptor;
import org.apache.hadoop.hive.metastore.api.Table;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class HiveEntityFactory {
  public static Table buildTable(
      String entityName,
      TableType tableType,
      String location,
      String... partitionColumnNames) {
    return buildTable(new EntityName(entityName), tableType, location, partitionColumnNames);
  }

  public static Table buildTable(
      EntityName entityName,
      TableType tableType,
      String location,
      String... partitionColumnNames) {
    Table table = new Table();
    table.setCatName(entityName.getCatalogName());
    table.setDbName(entityName.getDbName());
    table.setTableName(entityName.getEntityName());
    table.setTableType(tableType.toString());

    List<FieldSchema> partitionKeys = Arrays.stream(partitionColumnNames)
        .map(field -> new FieldSchema(field, "int", ""))
        .collect(Collectors.toList());
    table.setPartitionKeys(partitionKeys);

    StorageDescriptor sd = new StorageDescriptor();
    sd.setLocation(location);

    table.setSd(sd);
    return table;
  }

  public static Database buildDb(String entityName, String location) {
    return buildDb(new EntityName(entityName), location);
  }

  public static Database buildDb(EntityName entityName, String location) {
    Database db = new Database();
    db.setCatalogName(entityName.getCatalogName());
    db.setName(entityName.getDbName());
    db.setLocationUri(location);
    return db;
  }

  public static Function buildFunction(String name) {
    EntityName entityName = new EntityName(name);

    Function function = new Function();
    function.setCatName(entityName.getCatalogName());
    function.setDbName(entityName.getDbName());
    function.setFunctionName(entityName.getEntityName());
    function.setFunctionType(FunctionType.JAVA);
    return function;
  }

  public static Partition buildPartition(String tableName, String... values) {
    EntityName entityName = new EntityName(tableName);

    Partition partition = new Partition();
    partition.setCatName(entityName.getCatalogName());
    partition.setDbName(entityName.getDbName());
    partition.setTableName(entityName.getEntityName());
    partition.setValues(Arrays.asList(values));

    return partition;
  }

  public static SQLPrimaryKey buildPrimaryKey(String tableName, String columnName) {
    SQLPrimaryKey constraint = new SQLPrimaryKey();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setTable_db(entityName.getDbName());
    constraint.setTable_name(entityName.getEntityName());
    constraint.setColumn_name(columnName);
    constraint.setPk_name("primary_" + columnName);

    return constraint;
  }

  public static SQLForeignKey buildForeignKey(String tableName, String columnName) {
    SQLForeignKey constraint = new SQLForeignKey();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setFktable_db(entityName.getDbName());
    constraint.setFktable_name(entityName.getEntityName());
    constraint.setFkcolumn_name(columnName);
    constraint.setFk_name("foreign_" + columnName);

    return constraint;
  }

  public static SQLUniqueConstraint buildUniqueConstraint(String tableName, String columnName) {
    SQLUniqueConstraint constraint = new SQLUniqueConstraint();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setTable_db(entityName.getDbName());
    constraint.setTable_name(entityName.getEntityName());
    constraint.setColumn_name(columnName);
    constraint.setUk_name("unique_" + columnName);

    return constraint;
  }

  public static SQLNotNullConstraint buildNotNullConstraint(String tableName, String columnName) {
    SQLNotNullConstraint constraint = new SQLNotNullConstraint();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setTable_db(entityName.getDbName());
    constraint.setTable_name(entityName.getEntityName());
    constraint.setColumn_name(columnName);
    constraint.setNn_name("not_null_" + columnName);

    return constraint;
  }

  public static SQLDefaultConstraint buildDefaultConstraint(String tableName, String columnName) {
    SQLDefaultConstraint constraint = new SQLDefaultConstraint();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setTable_db(entityName.getDbName());
    constraint.setTable_name(entityName.getEntityName());
    constraint.setColumn_name(columnName);
    constraint.setDc_name("default_" + columnName);

    return constraint;
  }

  public static SQLCheckConstraint buildCheckConstraint(String tableName, String columnName) {
    SQLCheckConstraint constraint = new SQLCheckConstraint();
    EntityName entityName = new EntityName(tableName);

    constraint.setCatName(entityName.getCatalogName());
    constraint.setTable_db(entityName.getDbName());
    constraint.setTable_name(entityName.getEntityName());
    constraint.setColumn_name(columnName);
    constraint.setDc_name("check_" + columnName);

    return constraint;
  }
}
