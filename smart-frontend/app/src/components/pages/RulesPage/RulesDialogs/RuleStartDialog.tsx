/*
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
import React from 'react';
import { Dialog } from '@uikit';
import { useDispatch, useStore } from '@hooks';
import { closeStartRuleDialog, startRuleWithUpdate } from '@store/adh/rules/rulesActionsSlice';

const RuleStartDialog: React.FC = () => {
  const dispatch = useDispatch();
  const rule = useStore(({ adh }) => adh.rulesActions.startDialog.rule);
  const isOpen = !!rule;

  const closeDialog = () => {
    dispatch(closeStartRuleDialog());
  };
  const handleDelete = () => {
    if (rule) {
      dispatch(startRuleWithUpdate(rule.id));
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onOpenChange={closeDialog}
      title="Are you sure you want to start rule?"
      onAction={handleDelete}
      actionButtonLabel="Start"
    />
  );
};

export default RuleStartDialog;
