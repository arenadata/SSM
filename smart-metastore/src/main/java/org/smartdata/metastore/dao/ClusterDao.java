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
package org.smartdata.metastore.dao;

import org.smartdata.metastore.queries.sort.ClusterSortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.request.ClusterSearchRequest;

import java.util.Optional;

public interface ClusterDao
    extends Searchable<ClusterSearchRequest, ClusterInfo, ClusterSortField> {

  Optional<ClusterInfo> getById(long id);

  /**
   * Inserts the cluster ignoring its id.
   *
   * @return generated id of the cluster
   */
  long insert(ClusterInfo cluster);

  /**
   * Updates all the fields of the cluster with the same id, except the creation time.
   *
   * @return true if the cluster was found and updated
   */
  boolean update(ClusterInfo cluster);
}
