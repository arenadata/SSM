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
package org.smartdata.integration;

import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.ClusterNodeDto;
import org.smartdata.client.generated.model.ClusterNodesDto;
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.RegistrationTimeIntervalDto;
import org.smartdata.integration.api.ClusterApiWrapper;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TestClusterRestApi extends IntegrationTestBase {

  private ClusterApiWrapper apiClient;

  @Before
  public void createApi() {
    apiClient = new ClusterApiWrapper();
  }

  @Test
  public void testGetClusterNodes() {
    ClusterNodesDto clusterNodes = apiClient.getClusterNodes();

    List<ClusterNodeDto> items = clusterNodes.getItems();
    assertEquals(1L, clusterNodes.getTotal().longValue());
    assertEquals(1, items.size());
    assertEquals("ActiveSSMServer@127.0.0.1:7051", items.get(0).getId());
    assertEquals("127.0.0.1", items.get(0).getHost());
    assertEquals(7051, items.get(0).getPort().longValue());
    assertEquals("LOCAL", items.get(0).getExecutorType().getValue());
    assertNotNull(items.get(0).getRegistrationTime());
    assertEquals(10, items.get(0).getExecutorsCount().longValue());
    assertEquals(0, items.get(0).getCmdletsExecuted().longValue());
    // TODO test depends on config with these checks?
  }

  @Test
  public void testGetNodesPagination() {
    ClusterNodesDto clusterNodes = apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ClusterNodesDto.class);

    assertEquals(1L, clusterNodes.getTotal().longValue());
    assertEquals(0, clusterNodes.getItems().size());
  }

  @Test
  public void testGetNodesFilterByRegistrationTime() {
    long end = System.currentTimeMillis();
    long hourInMs = 3600000;
    long start = end - hourInMs;

    ClusterNodesDto clusterNodes = apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request
            .addQueryParam(RegistrationTimeIntervalDto.JSON_PROPERTY_REGISTRATION_TIME_FROM, start)
            .addQueryParam(RegistrationTimeIntervalDto.JSON_PROPERTY_REGISTRATION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ClusterNodesDto.class);

    assertEquals(1L, clusterNodes.getTotal().longValue());
    assertEquals(1, clusterNodes.getItems().size());

    clusterNodes = apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request
            .addQueryParam(RegistrationTimeIntervalDto.JSON_PROPERTY_REGISTRATION_TIME_FROM, end)
            .addQueryParam(RegistrationTimeIntervalDto.JSON_PROPERTY_REGISTRATION_TIME_TO, end + hourInMs))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ClusterNodesDto.class);

    assertEquals(0, clusterNodes.getTotal().longValue());
    assertEquals(0, clusterNodes.getItems().size());
  }

  @Test
  public void testGetNodesSortByIncorrectQuery() {
    apiClient.rawClient()
        .getClusterNodes()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetNodesPaginationWithIncorrectValue() {
    apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getClusterNodes()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }
}
