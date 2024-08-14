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
import org.smartdata.client.generated.model.CmdletDto;
import org.smartdata.client.generated.model.CmdletStateDto;
import org.smartdata.client.generated.model.CmdletsDto;
import org.smartdata.integration.api.CmdletsApiWrapper;

import java.time.Duration;

import static org.junit.Assert.assertEquals;

public class TestCmdletRestApi extends IntegrationTestBase {

  private CmdletsApiWrapper apiClient;

  @Before
  public void createApi() {
    apiClient = new CmdletsApiWrapper();
  }

  @Test
  public void testSubmitGetCmdlet() {
    createFile("/tmp/text.txt");

    String cmdletText = "read -file /tmp/text.txt; delete -file /tmp/text.txt";
    CmdletDto createdCmdlet = apiClient.submitCmdlet(cmdletText);

    CmdletDto fetchedCmdlet = apiClient.waitTillCmdletFinished(
        createdCmdlet.getId(), Duration.ofMillis(100L), Duration.ofSeconds(1L));

    assertEquals(fetchedCmdlet.getId(), createdCmdlet.getId());
    assertEquals(cmdletText, fetchedCmdlet.getTextRepresentation());
    assertEquals(2, fetchedCmdlet.getActionIds().size());
    assertEquals(CmdletStateDto.DONE, fetchedCmdlet.getState());
  }

  @Test
  public void testSubmitGetCmdlets() {
    createFile("/tmp/text.txt");

    String cmdletText = "read -file /tmp/text.txt; delete -file /tmp/text.txt";
    CmdletDto createdCmdlet = apiClient.submitCmdlet(cmdletText);


    // we have to wait a bit, because of async cmdlets transfer
    // from in-memory cache to metastore
    retryUntil(
        () -> apiClient.getCmdlets().getTotal().longValue(),
        total -> total == 1,
        Duration.ofMillis(100),
        Duration.ofSeconds(1)
    );

    CmdletsDto fetchedCmdlets = apiClient.getCmdlets();

    assertEquals(1L, fetchedCmdlets.getItems().size());
    CmdletDto fetchedCmdlet = fetchedCmdlets.getItems().get(0);
    assertEquals(createdCmdlet.getId(), fetchedCmdlet.getId());
    assertEquals(cmdletText, fetchedCmdlet.getTextRepresentation());
  }

  @Test
  public void testDeleteCmdlet() {
    createFile("/tmp/text1.txt");

    String cmdletText = "sleep -ms 10000; read -file /tmp/text1.txt";
    CmdletDto createdCmdlet = apiClient.submitCmdlet(cmdletText);

    CmdletDto cmdlet = apiClient.getCmdlet(createdCmdlet.getId());

    assertEquals(createdCmdlet.getId(), cmdlet.getId());

    apiClient.deleteCmdlet(createdCmdlet.getId());

    // we have to wait a bit, because of async removal of cmdlet from in-memory cache
    retryUntil(
        () -> apiClient.rawClient()
            .getCmdlet()
            .idPath(createdCmdlet.getId())
            .execute(Response::andReturn),
        response -> response.getStatusCode() == HttpStatus.NOT_FOUND_404,
        Duration.ofMillis(100),
        Duration.ofSeconds(5)
    );
  }

  @Test
  public void testReturnNotFoundOnUnknownId() {
    apiClient.rawClient()
        .getCmdlet()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }
}
