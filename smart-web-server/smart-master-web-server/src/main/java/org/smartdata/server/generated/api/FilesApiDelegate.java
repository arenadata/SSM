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
package org.smartdata.server.generated.api;

import org.smartdata.server.generated.model.CachedFileSortDto;
import org.smartdata.server.generated.model.CachedFilesDto;
import org.smartdata.server.generated.model.CachedTimeIntervalDto;
import org.smartdata.server.generated.model.FileAccessCountsDto;
import org.smartdata.server.generated.model.HotFileSortDto;
import org.smartdata.server.generated.model.LastAccessedTimeIntervalDto;
import org.smartdata.server.generated.model.PageRequestDto;
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;
import javax.validation.Valid;

import java.util.List;
import java.util.Optional;

/**
 * A delegate to be called by the {@link FilesApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface FilesApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * GET /api/v2/files/access-counts : List access counts of files
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param pathLike The file path filter. May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param lastAccessedTime Time interval in which the file was accessed (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see FilesApi#getAccessCounts
     */
    default FileAccessCountsDto getAccessCounts(PageRequestDto pageRequest,
        List<@Valid HotFileSortDto> sort,
        String pathLike,
        LastAccessedTimeIntervalDto lastAccessedTime) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

    /**
     * GET /api/v2/files/cached : List cached files
     *
     * @param pageRequest  (optional)
     * @param sort Sort field names prefixed with &#39;-&#39; for descending order (optional)
     * @param pathLike The file path filter. May contain special characters like \&quot;/\&quot;, \&quot;&#39;\&quot;, so should be encoded. (optional)
     * @param lastAccessedTime Time interval in which the file was accessed (optional)
     * @param cachedTime Time interval in which the file was cached (optional)
     * @return OK (status code 200)
     *         or Data is filled incorrectly (status code 400)
     *         or Unauthorized (status code 401)
     * @see FilesApi#getCachedFiles
     */
    default CachedFilesDto getCachedFiles(PageRequestDto pageRequest,
        List<@Valid CachedFileSortDto> sort,
        String pathLike,
        LastAccessedTimeIntervalDto lastAccessedTime,
        CachedTimeIntervalDto cachedTime) throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
