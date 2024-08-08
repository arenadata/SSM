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

import com.google.common.collect.ImmutableMap;
import lombok.RequiredArgsConstructor;
import org.smartdata.ranger.SsmResourceAccessType;
import org.smartdata.ranger.authorizer.RangerSsmAuthorizer;
import org.smartdata.ranger.authorizer.request.RangerAuthorizeRequest;
import org.smartdata.ranger.authorizer.request.RangerOperationDto;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import javax.ws.rs.HttpMethod;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.smartdata.ranger.SsmRangerResource.ACTION;
import static org.smartdata.ranger.SsmRangerResource.AUDIT;
import static org.smartdata.ranger.SsmRangerResource.CLUSTER;
import static org.smartdata.ranger.SsmRangerResource.RULE;

@RequiredArgsConstructor
public class RangerAuthorizationManager
    implements AuthorizationManager<RequestAuthorizationContext> {

  private static final String ALL_VALUES_EXPRESSION = "*";
  private static final
  Map<Pattern, Map<String, Function<RequestAuthorizationContext, RangerOperationDto>>>
      OPERATION_MAP =
      new HashMap<Pattern, Map<String,
          Function<RequestAuthorizationContext, RangerOperationDto>>>() {{
        //cluster
        put(Pattern.compile("^/api/v2/cluster/nodes$"), ImmutableMap.of(HttpMethod.GET,
            request -> CLUSTER.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION)));
        //rule
        put(Pattern.compile("^/api/v2/rules$"), ImmutableMap.of(
            HttpMethod.POST,
            request -> RULE.getRangerOperationDto(SsmResourceAccessType.CREATE,
                ALL_VALUES_EXPRESSION),
            HttpMethod.GET,
            request -> RULE.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION)));
        put(Pattern.compile("^/api/v2/rules/\\d+$"), ImmutableMap.of(
            HttpMethod.GET,
            request -> RULE.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION),
            HttpMethod.DELETE,
            request -> RULE.getRangerOperationDto(SsmResourceAccessType.DELETE,
                ALL_VALUES_EXPRESSION)));
        //action
        put(Pattern.compile("^/api/v2/actions$"), ImmutableMap.of(
            HttpMethod.POST,
            request -> ACTION.getRangerOperationDto(SsmResourceAccessType.SUBMIT,
                ALL_VALUES_EXPRESSION),
            HttpMethod.GET,
            request -> ACTION.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION)));
        put(Pattern.compile("^/api/v2/actions/\\d+$"), ImmutableMap.of(
            HttpMethod.GET,
            request -> ACTION.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION)
        ));
        //audit
        put(Pattern.compile("^/api/v2/audit/events$"), ImmutableMap.of(HttpMethod.GET,
            request -> AUDIT.getRangerOperationDto(SsmResourceAccessType.VIEW,
                ALL_VALUES_EXPRESSION)));
      }};

  private final RangerSsmAuthorizer rangerSsmAuthorizer;

  @Override
  public AuthorizationDecision check(Supplier<Authentication> authentication,
                                     RequestAuthorizationContext request) {
    return new AuthorizationDecision(
        OPERATION_MAP.entrySet().stream()
            .filter(entry -> entry.getKey().matcher(request.getRequest().getServletPath()).find())
            .map(entry -> Optional.ofNullable(entry.getValue().get(
                    request.getRequest().getMethod()))
                .map(func -> rangerSsmAuthorizer.authorize(
                    new RangerAuthorizeRequest(authentication.get().getName(),
                        func.apply(request)))))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .findAny()
            .orElse(true));
  }
}
