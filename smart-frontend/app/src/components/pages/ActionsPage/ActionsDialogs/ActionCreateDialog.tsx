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
import { closeCreateActionDialog, createActionWithUpdate } from '@store/adh/actions/actionsActionsSlice';
import { FooterDialog, MultilineInput } from '@uikit';
import { SpinnerPanel } from '@uikit/Spinner/Spinner';

const ActionCreateDialog: React.FC = () => {
  const dispatch = useDispatch();
  const isOpen = useStore(({ adh }) => adh.actionsActions.createDialog.isOpen);
  const isActionInProgress = useStore(({ adh }) => adh.actionsActions.isActionInProgress);

  const [actionText, setActionText] = useState('');

  useEffect(() => {
    // clear when close dialog
    if (!isOpen) {
      setActionText('');
    }
  }, [isOpen, setActionText]);

  const closeDialog = () => {
    dispatch(closeCreateActionDialog());
  };

  const handleChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    setActionText(event.target.value);
  };

  const handleRun = () => {
    dispatch(createActionWithUpdate(actionText));
  };

  return (
    <FooterDialog
      isOpen={isOpen}
      onOpenChange={closeDialog}
      title="Submit action"
      actionButtonLabel="Run"
      onAction={handleRun}
    >
      <MultilineInput value={actionText} onChange={handleChange} disabled={isActionInProgress} />
      {isActionInProgress && <SpinnerPanel />}
    </FooterDialog>
  );
};

export default ActionCreateDialog;
