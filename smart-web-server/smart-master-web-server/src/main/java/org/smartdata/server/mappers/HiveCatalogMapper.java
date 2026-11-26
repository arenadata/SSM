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
package org.smartdata.server.mappers;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValueMappingStrategy;
import org.mapstruct.ReportingPolicy;
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.server.generated.model.HiveDatabaseDto;
import org.smartdata.server.generated.model.HiveDatabasesDto;
import org.smartdata.server.generated.model.HiveTableDto;
import org.smartdata.server.generated.model.HiveTablesDto;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface HiveCatalogMapper extends SmartMapper {

  HiveDatabaseDto toHiveDatabaseDto(HiveDatabaseInfo database);

  HiveDatabasesDto toHiveDatabasesDto(SearchResult<HiveDatabaseInfo> searchResult);

  HiveTableDto toHiveTableDto(HiveTableInfo table);

  HiveTablesDto toHiveTablesDto(SearchResult<HiveTableInfo> searchResult);

  @BeanMapping(nullValueMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT)
  HiveDatabaseSearchRequest toDatabaseSearchRequest(String nameLike);

  @BeanMapping(nullValueMappingStrategy = NullValueMappingStrategy.RETURN_DEFAULT)
  @Mapping(target = "dbName", ignore = true)
  HiveTableSearchRequest toTableSearchRequest(List<String> dbNames, String nameLike);
}
