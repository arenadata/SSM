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
package org.smartdata.server;

import org.junit.After;
import org.junit.Before;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.conf.SmartFsType;
import org.smartdata.ozone.OzoneClusterHarness;

import java.io.IOException;

import static org.smartdata.conf.SmartConfKeys.SMART_FS_TYPE;

public class OzoneSmartClusterHarness extends OzoneClusterHarness {
  protected SmartServer ssm;
  protected SmartConf smartConf;

  @Before
  public void initSsm() throws Exception {
    // Set db used
    smartConf = new SmartConf(ozoneConf);
    smartConf.set(SMART_FS_TYPE, SmartFsType.OZONE.toString());
    smartConf.set(SmartConfKeys.SMART_OZONE_RPC_SERVER_KEY,
        ozoneContainer.getOmRpcAddress());

    // rpcServer start in SmartServer
    ssm = SmartServer.launchWith(smartConf);
  }

  @After
  public void shutdown() throws IOException {
    if (ssm != null) {
      ssm.shutdown();
    }
  }
}
