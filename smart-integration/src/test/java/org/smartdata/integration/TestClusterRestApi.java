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

import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.ClusterNodeDto;
import org.smartdata.client.generated.model.ClusterNodesDto;
import org.smartdata.integration.api.ClusterApiWrapper;

import java.util.List;

import static org.junit.Assert.assertEquals;

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
    assertEquals("127.0.0.1", items.get(0).getHost());
  }
}
