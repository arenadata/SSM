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


import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.util.Collection;

public interface FileAccessDao extends
    Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> {
  String TABLE_NAME = "file_access";
  String FILE_ID_FIELD = "fid";
  String ACCESS_COUNT_FIELD = "count";
  String ACCESS_TIME_FIELD = "access_time";

  void insert(Collection<AggregatedAccessCounts> aggregatedAccessCounts) throws MetaStoreException;

  void updateFileIds(long fidSrc, long fidDest) throws MetaStoreException;

}
