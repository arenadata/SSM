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
package org.smartdata.ranger.authorizer.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.smartdata.ranger.authorizer.RangerSsmAuthorizer;
import org.smartdata.ranger.authorizer.request.RangerAuthorizeRequest;
import org.smartdata.ranger.plugin.impl.RangerSsmPlugin;

import java.util.Date;

@Slf4j
public class RangerSsmAuthorizerImpl implements RangerSsmAuthorizer {

  private final RangerSsmPlugin ssmPlugin;

  public RangerSsmAuthorizerImpl() {
    log.debug("Trying to create RangerSsmAuthorizer");
    ssmPlugin = RangerSsmPlugin.getInstance();
    log.debug("RangerSsmAuthorizer created");
  }

  @Override
  public boolean authorize(RangerAuthorizeRequest request) {
    log.debug("Perform authorization checking [user={}],[resources={}],[accessType={}]",
        request.getUser(), request.getOperationDto().getResources(),
        request.getOperationDto().getAccessType());
    RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
    rangerRequest.setUser(request.getUser());
    rangerRequest.setAccessType(request.getOperationDto().getAccessType());
    rangerRequest.setAccessTime(new Date());
    RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
    request.getOperationDto().getResources().forEach(resource::setValue);
    rangerRequest.setResource(resource);
    RangerAccessResult result = ssmPlugin.isAccessAllowed(rangerRequest);
    boolean checkResult = result != null && result.getIsAllowed();
    log.debug("Authorization check [result={}]", checkResult);
    return checkResult;
  }
}