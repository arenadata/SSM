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
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.smartdata.ranger.SsmResourceAccessType;
import org.smartdata.ranger.authorizer.RangerSsmAuthorizer;
import org.smartdata.ranger.authorizer.request.RangerAuthorizeRequest;
import org.smartdata.ranger.authorizer.request.RangerOperationDto;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RangerAuthorizationManagerTest {
  private final RangerSsmAuthorizer rangerSsmAuthorizer = mock(RangerSsmAuthorizer.class);
  private AuthorizationManager<RequestAuthorizationContext> authorizationManager;

  @Before
  public void setUp() {
    authorizationManager = new RangerAuthorizationManager(rangerSsmAuthorizer);
  }

  @Test
  public void testOperationEntriesFound() {
    String user = "user";
    ArgumentCaptor<RangerAuthorizeRequest> requestArgumentCaptor = ArgumentCaptor.forClass(
        RangerAuthorizeRequest.class);
    when(rangerSsmAuthorizer.authorize(requestArgumentCaptor.capture())).thenReturn(true);
    HttpServletRequest httpRequest1 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest2 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest3 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest4 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest5 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest6 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest7 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest8 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest9 = mock(HttpServletRequest.class);
    when(httpRequest1.getServletPath()).thenReturn("/api/v2/actions/11");
    when(httpRequest1.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest2.getServletPath()).thenReturn("/api/v2/cluster/nodes");
    when(httpRequest2.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest3.getServletPath()).thenReturn("/api/v2/rules");
    when(httpRequest3.getMethod()).thenReturn(HttpMethod.POST);

    when(httpRequest4.getServletPath()).thenReturn("/api/v2/rules/9");
    when(httpRequest4.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest5.getServletPath()).thenReturn("/api/v2/rules/2");
    when(httpRequest5.getMethod()).thenReturn(HttpMethod.DELETE);

    when(httpRequest6.getServletPath()).thenReturn("/api/v2/actions");
    when(httpRequest6.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest7.getServletPath()).thenReturn("/api/v2/actions/33");
    when(httpRequest7.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest8.getServletPath()).thenReturn("/api/v2/audit/events");
    when(httpRequest8.getMethod()).thenReturn(HttpMethod.GET);

    when(httpRequest9.getServletPath()).thenReturn("/api/v2/actions");
    when(httpRequest9.getMethod()).thenReturn(HttpMethod.POST);

    Authentication authentication = mock(Authentication.class);
    when(authentication.getName()).thenReturn(user);
    Map<RequestAuthorizationContext, RangerOperationDto> requests =
        new HashMap<RequestAuthorizationContext, RangerOperationDto>() {{
          put(new RequestAuthorizationContext(httpRequest1),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("action", "*")));
          put(new RequestAuthorizationContext(httpRequest2),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("cluster", "*")));
          put(new RequestAuthorizationContext(httpRequest3),
              new RangerOperationDto(SsmResourceAccessType.CREATE.name(),
                  ImmutableMap.of("rule", "*")));
          put(new RequestAuthorizationContext(httpRequest4),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("rule", "*")));
          put(new RequestAuthorizationContext(httpRequest5),
              new RangerOperationDto(SsmResourceAccessType.DELETE.name(),
                  ImmutableMap.of("rule", "*")));
          put(new RequestAuthorizationContext(httpRequest6),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("action", "*")));
          put(new RequestAuthorizationContext(httpRequest7),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("action", "*")));
          put(new RequestAuthorizationContext(httpRequest8),
              new RangerOperationDto(SsmResourceAccessType.VIEW.name(),
                  ImmutableMap.of("audit", "*")));
          put(new RequestAuthorizationContext(httpRequest9),
              new RangerOperationDto(SsmResourceAccessType.SUBMIT.name(),
                  ImmutableMap.of("action", "*")));
        }};

    requests.forEach((req, value) -> {
      AuthorizationDecision result = authorizationManager.check(() -> authentication, req);
      assertTrue(result.isGranted());
      RangerAuthorizeRequest rangerRequest = requestArgumentCaptor.getValue();
      assertEquals(user, rangerRequest.getUser());
      assertEquals(
          value,
          rangerRequest.getOperationDto());
    });
  }

  @Test
  public void testOperationNotFound() {
    String user = "user";
    HttpServletRequest httpRequest1 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest2 = mock(HttpServletRequest.class);
    HttpServletRequest httpRequest3 = mock(HttpServletRequest.class);
    when(httpRequest1.getServletPath()).thenReturn("/api/v2/actions/11/test");
    when(httpRequest1.getMethod()).thenReturn(HttpMethod.GET);
    when(httpRequest2.getServletPath()).thenReturn("/api/v2/rules/22/test");
    when(httpRequest2.getMethod()).thenReturn(HttpMethod.GET);
    when(httpRequest3.getServletPath()).thenReturn("/api/v2/actions/test");
    when(httpRequest3.getMethod()).thenReturn(HttpMethod.GET);

    when(rangerSsmAuthorizer.authorize(any())).thenReturn(false);
    List<RequestAuthorizationContext> requests =
        Arrays.asList(new RequestAuthorizationContext(httpRequest1),
            new RequestAuthorizationContext(httpRequest2),
            new RequestAuthorizationContext(httpRequest3)
        );
    Authentication authentication = mock(Authentication.class);
    when(authentication.getName()).thenReturn(user);

    requests.forEach(req -> {
      AuthorizationDecision result = authorizationManager.check(() -> authentication, req);
      assertTrue(result.isGranted());
    });
  }
}
