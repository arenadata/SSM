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
package org.smartdata.server.security;

import lombok.RequiredArgsConstructor;
import org.smartdata.ranger.authorizer.RangerSsmAuthorizer;
import org.smartdata.ranger.authorizer.request.RangerAuthorizeRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Collections;
import java.util.function.Supplier;

@RequiredArgsConstructor
public class RangerAuthorizationManager
    implements AuthorizationManager<RequestAuthorizationContext> {

  private final RangerSsmAuthorizer rangerSsmAuthorizer;

  @Override
  public AuthorizationDecision check(Supplier<Authentication> authentication,
                                     RequestAuthorizationContext request) {

    return new AuthorizationDecision(rangerSsmAuthorizer.authorize(
        new RangerAuthorizeRequest(authentication.get().getName(),
            Collections.emptyList(),
            request.getRequest().getServletPath(),
            request.getRequest().getMethod())));
  }
}
