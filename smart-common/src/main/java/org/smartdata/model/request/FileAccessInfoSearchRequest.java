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
package org.smartdata.model.request;

import lombok.Builder;
import lombok.Data;
import lombok.Singular;
import lombok.With;
import org.smartdata.model.TimeInterval;

import java.util.List;
import java.util.Set;

@Data
@Builder
@With
public class FileAccessInfoSearchRequest {
  @Singular(ignoreNullCollections = true)
  private final List<Long> ids;
  private final String pathLike;
  private final TimeInterval lastAccessedTime;
  private final Set<String> accessCountTables;

  public static FileAccessInfoSearchRequest noFilters() {
    return builder().build();
  }
}
