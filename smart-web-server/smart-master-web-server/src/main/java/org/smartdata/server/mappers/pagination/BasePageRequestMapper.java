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

import org.mapstruct.Mapping;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.SortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.server.generated.model.PageRequestDto;

import java.util.List;

public interface BasePageRequestMapper<
    SourceT extends Enum<SourceT>,
    TargetT extends SortField> {

  String DESC_SORT_COLUMN_PREFIX = "-";

  PageRequest<TargetT> toPageRequest(PageRequestDto dto, List<SourceT> sortColumns);

  @Mapping(source = ".", target = "order")
  @Mapping(source = ".", target = "column")
  Sorting<TargetT> toSorting(SourceT sortColumn);

  TargetT toSortField(SourceT sortColumn);

  default Sorting.Order toOrder(SourceT sortColumn) {
    return sortColumn.toString().startsWith(DESC_SORT_COLUMN_PREFIX)
        ? Sorting.Order.DESC
        : Sorting.Order.ASC;
  }
}
