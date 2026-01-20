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
package org.smartdata.action;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Actions registry. Singleton.
 */
@Slf4j
public class ActionRegistry {
  @Getter
  private final Set<ActionMetadata> actionMetadata;
  private final Map<String, Class<? extends SmartAction>> actions;

  public ActionRegistry(Collection<ActionFactory> factories) {
    this.actions = new HashMap<>();
    this.actionMetadata = new HashSet<>();

    factories.stream()
        .map(ActionFactory::getSupportedActions)
        .forEach(actions::putAll);

    factories.stream()
        .map(ActionFactory::getActionMetadata)
        .forEach(actionMetadata::addAll);
  }

  public Set<String> registeredActions() {
    return actions.keySet();
  }

  public boolean isRegistered(String name) {
    return actions.containsKey(name);
  }

  public SmartAction createAction(String name) throws ActionException {
    if (!isRegistered(name)) {
      throw new ActionException("Unregistered action " + name);
    }

    try {
      SmartAction smartAction = actions.get(name).newInstance();
      smartAction.setName(name);
      return smartAction;
    } catch (Exception e) {
      log.error("Create {} action failed", name, e);
      throw new ActionException(e);
    }
  }
}
