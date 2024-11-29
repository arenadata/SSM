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
import React, { useCallback, useEffect, useRef } from 'react';
import { useDispatch, useStore } from '@hooks';
import { closeCreateRuleDialog, createRuleWithUpdate } from '@store/adh/rules/rulesActionsSlice';
import { FooterDialog } from '@uikit';
import { SpinnerPanel } from '@uikit/Spinner/Spinner';
import MonacoCodeEditor from '@uikit/MonacoCodeEditor/MonacoCodeEditor';
import { type IStandaloneCodeEditor, monaco } from '@uikit/MonacoCodeEditor/MonacoCodeEditor.types';

const RuleCreateDialog: React.FC = () => {
  const dispatch = useDispatch();
  const isOpen = useStore(({ adh }) => adh.rulesActions.createDialog.isOpen);
  const isActionInProgress = useStore(({ adh }) => adh.rulesActions.isActionInProgress);

  const ruleText = useRef('');

  useEffect(() => {
    // clear when close dialog
    if (!isOpen) {
      ruleText.current = '';
    }
  }, [isOpen]);

  const closeDialog = () => {
    dispatch(closeCreateRuleDialog());
  };

  const handleChange = useCallback((value: string) => {
    ruleText.current = value;
  }, []);

  const handleCreate = () => {
    dispatch(createRuleWithUpdate(ruleText.current));
  };

  const handleMount = (editor: IStandaloneCodeEditor) => {
    editor.addCommand(monaco.KeyMod.Shift | monaco.KeyCode.Enter, handleCreate);
  };

  return (
    <FooterDialog
      isOpen={isOpen}
      onOpenChange={closeDialog}
      title="Create Rule"
      actionButtonLabel="Create"
      onAction={handleCreate}
    >
      <MonacoCodeEditor
        language="ssmrule"
        initialValue={ruleText.current}
        theme="ssmruleTheme"
        showMinimap={false}
        onMount={handleMount}
        onChange={handleChange}
      />
      {isActionInProgress && <SpinnerPanel />}
    </FooterDialog>
  );
};

export default RuleCreateDialog;
