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
package org.smartdata.server.engine.cmdlet;

import org.junit.Assert;
import org.junit.Test;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.CmdletInfo;
import org.smartdata.server.MiniSmartClusterHarness;

public class TestActionRpc extends MiniSmartClusterHarness {

  @Test
  public void testActionProgress() throws Exception {
    waitTillSSMExitSafeMode();

    long cmdId = ssm.getCmdletManager().submitCmdlet("sleep -ms 6000").getId();
    CmdletInfo cinfo = ssm.getCmdletManager().getCmdletInfoHandler().getCmdletInfoOrThrow(cmdId);
    long actId = cinfo.getActionIds().get(0);
    ActionInfo actionInfo;
    while (true) {
      actionInfo = ssm.getCmdletManager().getActionInfoHandler().getActionInfo(actId);
      if (actionInfo.isFinished()) {
        Assert.fail("No intermediate progress observed.");
      }
      if (actionInfo.getProgress() > 0 && actionInfo.getProgress() < 1.0) {
        return;
      }
      Thread.sleep(500);
    }
  }
}
