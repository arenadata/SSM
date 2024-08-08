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
package org.smartdata.ranger;

import com.google.common.collect.Sets;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.smartdata.ranger.authorizer.request.RangerOperationDto;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Getter
@RequiredArgsConstructor
public enum SsmRangerResource {
  CLUSTER(Collections.singleton(SsmResourceAccessType.VIEW)),
  RULE(Sets.newHashSet(SsmResourceAccessType.CREATE, SsmResourceAccessType.VIEW,
      SsmResourceAccessType.EDIT, SsmResourceAccessType.DELETE)),
  ACTION(Sets.newHashSet(SsmResourceAccessType.SUBMIT, SsmResourceAccessType.VIEW)),
  AUDIT(Collections.singleton(SsmResourceAccessType.VIEW));

  private final Set<SsmResourceAccessType> accessTypes;

  public RangerOperationDto getRangerOperationDto(SsmResourceAccessType accessType,
                                                  String entityId) {
    if (!accessTypes.contains(accessType)) {
      throw new IllegalArgumentException("Unknown action: " + accessType);
    }
    Map<String, Object> resources = new HashMap<>();
    Optional.ofNullable(entityId)
        .ifPresent(value -> resources.put(this.name().toLowerCase(), value));
    return new RangerOperationDto(accessType.name(), resources);
  }
}
