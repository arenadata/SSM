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

import org.apache.commons.collections.CollectionUtils;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;
import org.mapstruct.ReportingPolicy;
import org.mapstruct.ValueMapping;
import org.smartdata.metastore.queries.sort.ClusterNodeSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.server.generated.model.ClusterSortDto;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.smartdata.server.generated.model.ClusterSortDto.STATUS;
import static org.smartdata.server.generated.model.ClusterSortDto._STATUS;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ClusterNodePageRequestMapper
    extends BasePageRequestMapper<ClusterSortDto, ClusterNodeSortField> {

  @ValueMapping(source = "REGISTRATIONTIME", target = "REGISTRATION_TIME")
  @ValueMapping(source = "EXECUTORSCOUNT", target = "EXECUTORS")
  @ValueMapping(source = "_ID", target = "ID")
  @ValueMapping(source = "_REGISTRATIONTIME", target = "REGISTRATION_TIME")
  @ValueMapping(source = "_EXECUTORSCOUNT", target = "EXECUTORS")
  @ValueMapping(source = "STATUS", target = MappingConstants.THROW_EXCEPTION)
  @ValueMapping(source = "_STATUS", target = MappingConstants.THROW_EXCEPTION)
  ClusterNodeSortField toSortField(ClusterSortDto sortColumn);


  default List<Sorting<ClusterNodeSortField>> toSortings(List<ClusterSortDto> sortColumns) {
    if (CollectionUtils.isEmpty(sortColumns)) {
      return Collections.emptyList();
    }

    return sortColumns.stream()
        .filter(column -> column != STATUS && column != _STATUS)
        .map(this::toSorting)
        .collect(Collectors.toList());
  }
}
