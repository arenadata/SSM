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
import org.smartdata.metastore.queries.sort.RuleSortField;
import org.smartdata.server.generated.model.RuleSortDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface RulesPageRequestMapper
    extends BasePageRequestMapper<RuleSortDto, RuleSortField> {

  @ValueMapping(source = "SUBMITTIME", target = "SUBMIT_TIME")
  @ValueMapping(source = "LASTACTIVATIONTIME", target = "LAST_CHECK_TIME")
  @ValueMapping(source = "ACTIVATIONCOUNT", target = "CHECKED_COUNT")
  @ValueMapping(source = "CMDLETSGENERATED", target = "GENERATED_CMDLETS")
  @ValueMapping(source = "_ID", target = "ID")
  @ValueMapping(source = "_SUBMITTIME", target = "SUBMIT_TIME")
  @ValueMapping(source = "_LASTACTIVATIONTIME", target = "LAST_CHECK_TIME")
  @ValueMapping(source = "_ACTIVATIONCOUNT", target = "CHECKED_COUNT")
  @ValueMapping(source = "_CMDLETSGENERATED", target = "GENERATED_CMDLETS")
  @ValueMapping(source = "_STATE", target = "STATE")
  RuleSortField toSortField(RuleSortDto sortColumn);

}
