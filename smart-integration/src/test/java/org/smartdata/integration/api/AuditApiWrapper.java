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
package org.smartdata.integration.api;

import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.api.AuditApi;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.AuditEventsDto;

public class AuditApiWrapper {

  private final AuditApi apiClient;

  public AuditApiWrapper() {
    this.apiClient = ApiClient.api(ApiClient.Config.apiConfig()).audit();
  }

  public AuditEventsDto getAuditEvents() {
    return apiClient.getAuditEvents()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }
}
