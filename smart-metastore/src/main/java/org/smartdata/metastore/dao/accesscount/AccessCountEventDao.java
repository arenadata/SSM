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
package org.smartdata.metastore.dao.accesscount;


import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public interface AccessCountEventDao extends
    Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> {
  String FILE_ID_FIELD = "fid";
  String ACCESS_COUNT_FIELD = "count";
  String LAST_ACCESSED_TIME_FIELD = "last_accessed_time";

  void insert(
      AccessCountTable table,
      Collection<AggregatedAccessCounts> aggregatedAccessCounts) throws MetaStoreException;

  void validate(AccessCountTable table) throws MetaStoreException;

  void updateFileIds(List<AccessCountTable> accessCountTables,
                     long fidSrc, long fidDest) throws MetaStoreException;

  static String unionTablesQuery(List<AccessCountTable> tables) {
    return tables.stream()
        .map(AccessCountTable::getTableName)
        .collect(Collectors.joining(
            " UNION ALL SELECT * FROM ", "SELECT * FROM ", ""));
  }

  static String unionTablesQuery(Set<String> tables) {
    return tables.stream()
        .collect(Collectors.joining(
            " UNION ALL SELECT * FROM ", "SELECT * FROM ", ""));
  }
}
