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
package org.smartdata.ozone;

import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.File;

import static org.smartdata.ozone.OzoneClusterHarness.resourceAbsolutePath;

public class OzoneClusterCompose extends ComposeContainer {
  public static final String DEFAULT_COMPOSE_FILE = "docker-compose-ozone.yaml";

  private static final String OM_SERVICE = "om";
  private static final String SCM_SERVICE = "scm";
  private static final String DATANODE_SERVICE = "datanode";

  private static final int OM_PORT = 9862;
  private static final int SCM_PORT = 9876;
  private static final int DATANODE_PORT = 9864;

  public OzoneClusterCompose() {
    this(resourceAbsolutePath(DEFAULT_COMPOSE_FILE));
  }

  public OzoneClusterCompose(String composeFilePath) {
    super(new File(composeFilePath));

    withExposedService(DATANODE_SERVICE, DATANODE_PORT,
        Wait.forLogMessage(".*Ozone container server started.*", 1));
    withExposedService(SCM_SERVICE, SCM_PORT,
        Wait.forLogMessage(".*SCM exiting safe mode.*", 1));
    withExposedService(OM_SERVICE, OM_PORT,
        Wait.forLogMessage(".*Leader om1@.* is ready.*", 1));
  }

  public String getOmHost() {
    return getServiceHost(OM_SERVICE, OM_PORT);
  }

  public int getOmPort() {
    return getServicePort(OM_SERVICE, OM_PORT);
  }

  public String getOmRpcAddress() {
    return getOmHost() + ":" + getOmPort();
  }

}
