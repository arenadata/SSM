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
package org.smartdata.ranger.authorizer.request;

import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;

import java.util.Date;
import java.util.HashSet;

public class RangerSsmAccessRequest extends RangerAccessRequestImpl {

    public RangerSsmAccessRequest(RangerAuthorizeRequest request) {
        setUser(request.getUserName());
        if (!request.getUserGroups().isEmpty()) {
            super.setUserGroups(new HashSet<>(request.getUserGroups()));
        }
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue("path", request.getUrlPath());
        setResource(resource);
        setAccessType(request.getAccessMethod());
        setAction(request.getAccessMethod());
        setAccessTime(new Date());
    }
}
