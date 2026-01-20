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

import lombok.extern.slf4j.Slf4j;
import org.smartdata.action.annotation.ActionSignature;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A common action factory for action providers to use.
 */
@Slf4j
public abstract class AbstractActionFactory implements ActionFactory {
  private static final List<Class<? extends SmartAction>> COMMON_ACTIONS = Arrays.asList(
      EchoAction.class,
      SleepAction.class,
      ExecAction.class
  );

  @Override
  public Map<String, Class<? extends SmartAction>> getSupportedActions() {
    Map<String, Class<? extends SmartAction>> supportedActions = new HashMap<>();
    COMMON_ACTIONS.forEach(
        actionClass -> addActionInfo(supportedActions, actionClass));
    supportedActionClasses().forEach(
        actionClass -> addActionInfo(supportedActions, actionClass));

    return supportedActions;
  }

  @Override
  public Set<ActionMetadata> getActionMetadata() {
    Set<ActionMetadata> actionMetadata = new HashSet<>();
    COMMON_ACTIONS.forEach(action ->
        toActionMetadata(action).ifPresent(actionMetadata::add));
    supportedActionClasses().forEach(action ->
        toActionMetadata(action).ifPresent(actionMetadata::add));

    return actionMetadata;
  }

  protected abstract List<Class<? extends SmartAction>> supportedActionClasses();

  private Optional<ActionMetadata> toActionMetadata(Class<? extends SmartAction> actionClass) {
    return actionSignature(actionClass)
        .map(signature -> new ActionMetadata(signature.actionId(), signature.usage()));
  }

  private void addActionInfo(
      Map<String, Class<? extends SmartAction>> supportedActions,
      Class<? extends SmartAction> actionClass) {
    actionSignature(actionClass)
        .map(ActionSignature::actionId)
        .ifPresent(actionId -> supportedActions.put(actionId, actionClass));
  }

  private Optional<ActionSignature> actionSignature(Class<? extends SmartAction> actionClass) {
    return Optional.ofNullable(actionClass.getAnnotation(ActionSignature.class));
  }
}
