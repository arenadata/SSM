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
import React, { useEffect, useState } from 'react';
import { useDispatch, useStore } from '@hooks';
import { closeCreateRuleDialog, createRuleWithUpdate } from '@store/adh/rules/rulesActionsSlice';
import { FooterDialog, MultilineInput } from '@uikit';
import { SpinnerPanel } from '@uikit/Spinner/Spinner';

const RuleCreateDialog: React.FC = () => {
  const dispatch = useDispatch();
  const isOpen = useStore(({ adh }) => adh.rulesActions.createDialog.isOpen);
  const isActionInProgress = useStore(({ adh }) => adh.rulesActions.isActionInProgress);

  const [ruleText, setRuleText] = useState('');

  useEffect(() => {
    // clear when close dialog
    if (!isOpen) {
      setRuleText('');
    }
  }, [isOpen, setRuleText]);

  const closeDialog = () => {
    dispatch(closeCreateRuleDialog());
  };

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRuleText(event.target.value);
  };

  const handleCreate = () => {
    dispatch(createRuleWithUpdate(ruleText));
  };

  return (
    <FooterDialog
      isOpen={isOpen}
      onOpenChange={closeDialog}
      title="Create Rule"
      actionButtonLabel="Create"
      onAction={handleCreate}
    >
      <MultilineInput value={ruleText} onChange={handleChange} disabled={isActionInProgress} />
      {isActionInProgress && <SpinnerPanel />}
    </FooterDialog>
  );
};

export default RuleCreateDialog;
