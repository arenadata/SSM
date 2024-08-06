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
package org.smartdata.server.controller;

import lombok.RequiredArgsConstructor;
import org.smartdata.metastore.dao.accesscount.AccessCountTableManager;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;
import org.smartdata.server.generated.api.FilesApiDelegate;
import org.smartdata.server.generated.model.CachedFileSortDto;
import org.smartdata.server.generated.model.CachedFilesDto;
import org.smartdata.server.generated.model.CachedTimeIntervalDto;
import org.smartdata.server.generated.model.FileAccessCountsDto;
import org.smartdata.server.generated.model.HotFileSortDto;
import org.smartdata.server.generated.model.LastAccessedTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.smartdata.server.mappers.FileAccessInfoMapper;
import org.smartdata.server.mappers.pagination.FileAccessInfoPageRequestMapper;
import org.springframework.stereotype.Component;

import javax.validation.Valid;

import java.util.List;

@Component
@RequiredArgsConstructor
public class FilesControllerDelegate implements FilesApiDelegate {

  private final AccessCountTableManager accessCountTableManager;
  private final FileAccessInfoMapper fileInfoMapper;
  private final FileAccessInfoPageRequestMapper pageRequestMapper;
  private final CachedFilesControllerDelegate cachedFilesControllerDelegate;

  @Override
  public CachedFilesDto getCachedFiles(PageRequestDto pageRequestDto,
                                       List<@Valid CachedFileSortDto> sort,
                                       String pathLike,
                                       LastAccessedTimeIntervalDto lastAccessedTime,
                                       CachedTimeIntervalDto cachedTime) {
    return cachedFilesControllerDelegate.getCachedFiles(
        pageRequestDto, sort, pathLike, lastAccessedTime, cachedTime);
  }

  @Override
  public FileAccessCountsDto getAccessCounts(PageRequestDto pageRequestDto,
                                             List<@Valid HotFileSortDto> sort,
                                             String pathLike,
                                             LastAccessedTimeIntervalDto lastAccessedTime) {
    PageRequest<FileAccessInfoSortField> pageRequest =
        pageRequestMapper.toPageRequest(pageRequestDto, sort);

    FileAccessInfoSearchRequest searchRequest = fileInfoMapper.toSearchRequest(
        pathLike,
        lastAccessedTime);

    SearchResult<FileAccessInfo> searchResult =
        accessCountTableManager.search(searchRequest, pageRequest);
    return fileInfoMapper.toFileAccessCountsDto(searchResult);
  }
}
