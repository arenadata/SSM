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
import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.server.generated.model.CmdletSortDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface CmdletsPageRequestMapper
    extends BasePageRequestMapper<CmdletSortDto, CmdletSortField> {
  @ValueMapping(source = "RULEID", target = "RULE_ID")
  @ValueMapping(source = "SUBMISSIONTIME", target = "GENERATE_TIME")
  @ValueMapping(source = "STATECHANGEDTIME", target = "STATE_CHANGED_TIME")
  @ValueMapping(source = "_ID", target = "ID")
  @ValueMapping(source = "_RULEID", target = "RULE_ID")
  @ValueMapping(source = "_STATE", target = "STATE")
  @ValueMapping(source = "_SUBMISSIONTIME", target = "GENERATE_TIME")
  @ValueMapping(source = "_STATECHANGEDTIME", target = "STATE_CHANGED_TIME")
  CmdletSortField toSortField(CmdletSortDto sortColumn);
}
