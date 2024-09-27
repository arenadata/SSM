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
package org.smartdata.server.mappers.pagination;

import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;
import org.mapstruct.ValueMapping;
import org.smartdata.metastore.queries.sort.CachedFilesSortField;
import org.smartdata.server.generated.model.CachedFileSortDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface CachedFilePageRequestMapper
    extends BasePageRequestMapper<CachedFileSortDto, CachedFilesSortField> {

  @ValueMapping(source = "ID", target = "FILE_ID")
  @ValueMapping(source = "ACCESSCOUNT", target = "ACCESS_COUNT")
  @ValueMapping(source = "CACHEDTIME", target = "CACHED_TIME")
  @ValueMapping(source = "LASTACCESSTIME", target = "LAST_ACCESSED_TIME")
  @ValueMapping(source = "_ID", target = "FILE_ID")
  @ValueMapping(source = "_PATH", target = "PATH")
  @ValueMapping(source = "_ACCESSCOUNT", target = "ACCESS_COUNT")
  @ValueMapping(source = "_CACHEDTIME", target = "CACHED_TIME")
  @ValueMapping(source = "_LASTACCESSTIME", target = "LAST_ACCESSED_TIME")
  CachedFilesSortField toSortField(CachedFileSortDto sortColumn);
}
