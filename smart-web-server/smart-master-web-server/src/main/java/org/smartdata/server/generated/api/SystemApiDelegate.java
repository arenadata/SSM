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

import org.smartdata.server.generated.model.UserInfoDto;
import org.springframework.web.context.request.NativeWebRequest;

import javax.annotation.Generated;

import java.util.Optional;

/**
 * A delegate to be called by the {@link SystemApiController}}.
 * Implement this interface with a {@link org.springframework.stereotype.Service} annotated class.
 */
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public interface SystemApiDelegate {

    default Optional<NativeWebRequest> getRequest() {
        return Optional.empty();
    }

    /**
     * GET /api/v2/system/current-user : Get current logged in user
     *
     * @return OK (status code 200)
     *         or Unauthorized (status code 401)
     * @see SystemApi#getCurrentUser
     */
    default UserInfoDto getCurrentUser() throws Exception {
        throw new IllegalArgumentException("Not implemented");

    }

}
