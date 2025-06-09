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

import com.google.common.eventbus.Subscribe;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.server.engine.EngineEventBus;
import org.smartdata.server.engine.message.AddNodeMessage;
import org.smartdata.server.engine.message.NodeMessage;
import org.smartdata.server.engine.message.RemoveNodeMessage;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class CmdletDispatcherHelper {
  private static CmdletDispatcherHelper inst;
  private final List<NodeMessage> messages;
  private CmdletDispatcher dispatcher;

  public CmdletDispatcherHelper() {
    this.messages = new ArrayList<>();
    this.dispatcher = null;
  }

  public void register(CmdletDispatcher dispatcher) {
    synchronized (messages) {
      this.dispatcher = dispatcher;
      for (NodeMessage message : messages) {
        handleMessageOnDispatcher(message);
      }

      messages.clear();
    }
  }

  public void unregister() {
    synchronized (messages) {
      dispatcher = null;
    }
  }

  public static void init() {
    inst = new CmdletDispatcherHelper();
    EngineEventBus.register(inst);
  }

  /**
   * The instance will be registered by EngineEventBus.
   * Node add/remove event will be posted by SmartServer,
   * standby server and agent master.
   */
  public static CmdletDispatcherHelper getInst() {
    return inst;
  }

  @Subscribe
  public void onAddNodeMessage(AddNodeMessage msg) {
    onNodeMessage(msg);
  }

  @Subscribe
  public void onRemoveNodeMessage(RemoveNodeMessage msg) {
    onNodeMessage(msg);
  }

  private void onNodeMessage(NodeMessage msg) {
    synchronized (messages) {
      if (dispatcher == null) {
        // Dispatcher is not registered, but we need to keep message
        // in msgs and ask dispatcher to tackle in #register later.
        messages.add(msg);
        return;
      }

      handleMessageOnDispatcher(msg);
    }
  }

  private void handleMessageOnDispatcher(NodeMessage msg) {
    if (msg instanceof AddNodeMessage) {
      dispatcher.onNodeAdded((AddNodeMessage) msg);
    } else if (msg instanceof RemoveNodeMessage) {
      dispatcher.onNodeRemoved((RemoveNodeMessage) msg);
    } else {
      log.error("Unknown message of type {}: {}", msg.getClass().getName(), msg);
    }
  }
}
