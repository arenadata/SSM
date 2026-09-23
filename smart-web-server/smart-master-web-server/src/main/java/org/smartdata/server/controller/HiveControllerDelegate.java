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
package org.smartdata.server.controller;

import lombok.RequiredArgsConstructor;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.HiveDatabaseSortField;
import org.smartdata.metastore.queries.sort.HiveTableSortField;
import org.smartdata.server.engine.HiveCatalogManager;
import org.smartdata.server.generated.api.HiveApiDelegate;
import org.smartdata.server.generated.model.HiveDatabaseDto;
import org.smartdata.server.generated.model.HiveDatabaseSortDto;
import org.smartdata.server.generated.model.HiveDatabasesDto;
import org.smartdata.server.generated.model.HiveTableDto;
import org.smartdata.server.generated.model.HiveTableSortDto;
import org.smartdata.server.generated.model.HiveTablesDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.mappers.HiveCatalogMapper;
import org.smartdata.server.mappers.pagination.HiveDatabasePageRequestMapper;
import org.smartdata.server.mappers.pagination.HiveTablePageRequestMapper;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class HiveControllerDelegate implements HiveApiDelegate {

  private final HiveCatalogManager hiveCatalogManager;

  private final HiveCatalogMapper hiveCatalogMapper;
  private final HiveDatabasePageRequestMapper databasePageRequestMapper;
  private final HiveTablePageRequestMapper tablePageRequestMapper;

  @Override
  public HiveDatabasesDto getHiveDatabases(
      PageRequestDto pageRequestDto,
      List<HiveDatabaseSortDto> sort,
      String nameLike) throws Exception {
    PageRequest<HiveDatabaseSortField> pageRequest =
        databasePageRequestMapper.toPageRequest(pageRequestDto, sort);

    HiveDatabaseSearchRequest searchRequest =
        hiveCatalogMapper.toDatabaseSearchRequest(nameLike);

    return hiveCatalogMapper.toHiveDatabasesDto(
        hiveCatalogManager.searchDatabases(searchRequest, pageRequest));
  }

  @Override
  public HiveDatabaseDto getHiveDatabase(String dbName) throws Exception {
    return hiveCatalogMapper.toHiveDatabaseDto(
        hiveCatalogManager.getDatabase(dbName));
  }

  @Override
  public HiveTablesDto getHiveTables(
      PageRequestDto pageRequestDto,
      List<HiveTableSortDto> sort,
      List<String> dbNames,
      String nameLike) throws Exception {
    PageRequest<HiveTableSortField> pageRequest =
        tablePageRequestMapper.toPageRequest(pageRequestDto, sort);

    HiveTableSearchRequest searchRequest =
        hiveCatalogMapper.toTableSearchRequest(dbNames, nameLike);

    return hiveCatalogMapper.toHiveTablesDto(
        hiveCatalogManager.searchTables(searchRequest, pageRequest));
  }

  @Override
  public HiveTableDto getHiveTable(String dbName, String tableName) throws Exception {
    return hiveCatalogMapper.toHiveTableDto(
        hiveCatalogManager.getTable(dbName, tableName));
  }
}
