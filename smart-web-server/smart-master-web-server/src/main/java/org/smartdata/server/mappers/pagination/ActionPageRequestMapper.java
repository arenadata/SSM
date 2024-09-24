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
import org.smartdata.metastore.queries.sort.ActionSortField;
import org.smartdata.server.generated.model.ActionSortDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ActionPageRequestMapper
    extends BasePageRequestMapper<ActionSortDto, ActionSortField> {

  @ValueMapping(source = "EXECHOST", target = "EXEC_HOST")
  @ValueMapping(source = "SUBMISSIONTIME", target = "CREATE_TIME")
  @ValueMapping(source = "COMPLETIONTIME", target = "FINISH_TIME")
  @ValueMapping(source = "STATE", target = "STATUS")
  @ValueMapping(source = "_ID", target = "ID")
  @ValueMapping(source = "_EXECHOST", target = "EXEC_HOST")
  @ValueMapping(source = "_SUBMISSIONTIME", target = "CREATE_TIME")
  @ValueMapping(source = "_COMPLETIONTIME", target = "FINISH_TIME")
  @ValueMapping(source = "_STATE", target = "STATUS")
  @ValueMapping(source = "_SOURCE", target = "SOURCE")
  ActionSortField toSortField(ActionSortDto sortColumn);
}
