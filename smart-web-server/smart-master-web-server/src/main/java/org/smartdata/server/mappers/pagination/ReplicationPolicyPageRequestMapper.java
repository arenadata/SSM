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
import org.smartdata.metastore.queries.sort.ReplicationPolicySortField;
import org.smartdata.server.generated.model.ReplicationPolicySortDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ReplicationPolicyPageRequestMapper
    extends BasePageRequestMapper<ReplicationPolicySortDto, ReplicationPolicySortField> {

  @ValueMapping(source = "TARGETCLUSTERID", target = "TARGET_CLUSTER_ID")
  @ValueMapping(source = "CREATETIME", target = "CREATE_TIME")
  @ValueMapping(source = "UPDATETIME", target = "UPDATE_TIME")
  @ValueMapping(source = "_ID", target = "ID")
  @ValueMapping(source = "_NAME", target = "NAME")
  @ValueMapping(source = "_STATUS", target = "STATUS")
  @ValueMapping(source = "_TARGETCLUSTERID", target = "TARGET_CLUSTER_ID")
  @ValueMapping(source = "_CREATETIME", target = "CREATE_TIME")
  @ValueMapping(source = "_UPDATETIME", target = "UPDATE_TIME")
  ReplicationPolicySortField toSortField(ReplicationPolicySortDto sortColumn);
}
