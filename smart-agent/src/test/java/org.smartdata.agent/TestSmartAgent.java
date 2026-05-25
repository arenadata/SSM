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
package org.smartdata.agent;

import akka.actor.ActorRef;
import akka.actor.ActorSystem;
import akka.actor.Props;
import akka.testkit.JavaTestKit;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.protocol.message.StatusMessage;
import org.smartdata.server.engine.cmdlet.agent.ActorSystemHarness;
import org.smartdata.server.engine.cmdlet.agent.AgentConstants;
import org.smartdata.server.engine.cmdlet.agent.AgentUtils;
import org.smartdata.server.engine.cmdlet.agent.messages.AgentToMaster.RegisterNewAgent;
import org.smartdata.server.engine.cmdlet.agent.messages.MasterToAgent;

public class TestSmartAgent extends ActorSystemHarness {

  @Test
  public void testAgent() {
    ActorSystem system = getActorSystem();
    final int num = 2;
    JavaTestKit[] masters = new JavaTestKit[num];
    String[] masterPaths = new String[num];
    for (int i = 0; i < num; i++) {
      masters[i] = new JavaTestKit(system);
      masterPaths[i] = AgentUtils.getFullPath(system, masters[i].getRef().path());
    }
    SmartConf conf = new SmartConf();
    Config config = AgentUtils.overrideRemoteAddress(
        ConfigFactory.load(AgentConstants.AKKA_CONF_FILE),
        conf.get(SmartConfKeys.SMART_AGENT_ADDRESS_KEY)
    );

    ActorSystem agentSystem = ActorSystem.apply("SmartAgent", config);
    ActorRef agent = agentSystem.actorOf(
        Props.create(SmartAgent.AgentActor.class, masterPaths, conf)
    );
    try {
      masters[0].expectMsgClass(RegisterNewAgent.class);
      masters[0].reply(new MasterToAgent.AgentRegistered(new MasterToAgent.AgentId("test")));

      system.stop(masters[0].getRef());

      masters[1].expectMsgClass(RegisterNewAgent.class);
      masters[1].reply(new MasterToAgent.AgentRegistered(new MasterToAgent.AgentId("test2")));

      JavaTestKit statusReporter = new JavaTestKit(agentSystem);
      agent.tell(new TestStatusMessage(), statusReporter.getRef());
      statusReporter.expectMsgEquals("status reported");
    } finally {
      agentSystem.stop(agent);
      JavaTestKit.shutdownActorSystem(agentSystem);
    }
  }

  private static class TestStatusMessage implements StatusMessage {
    private static final long serialVersionUID = 1L;
  }
}
