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
package org.smartdata.server.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.CachedFileSearchRequest;
import org.smartdata.server.generated.model.CachedFileInfoDto;
import org.smartdata.server.generated.model.CachedFilesDto;
import org.smartdata.server.generated.model.CachedTimeIntervalDto;
import org.smartdata.server.generated.model.LastAccessedTimeIntervalDto;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface CachedFileMapper extends SmartMapper {

  @Mapping(source = "fid", target = "id")
  @Mapping(source = "fromTime", target = "cachedTime")
  @Mapping(source = "numAccessed", target = "accessCount")
  CachedFileInfoDto toCachedFileDto(CachedFileStatus status);

  CachedFilesDto toCachedFiles(SearchResult<CachedFileStatus> searchResult);

  CachedFileSearchRequest toSearchRequest(
      String pathLike,
      LastAccessedTimeIntervalDto lastAccessedTime,
      CachedTimeIntervalDto cachedTime);

  @Mapping(source = "lastAccessedTimeFrom", target = "from")
  @Mapping(source = "lastAccessedTimeTo", target = "to")
  TimeInterval toTimeInterval(LastAccessedTimeIntervalDto intervalDto);

  @Mapping(source = "cachedTimeFrom", target = "from")
  @Mapping(source = "cachedTimeTo", target = "to")
  TimeInterval toTimeInterval(CachedTimeIntervalDto intervalDto);
}
