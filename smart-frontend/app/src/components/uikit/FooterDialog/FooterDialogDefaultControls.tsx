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
import Button from '@uikit/Button/Button';
import ButtonGroup from '@uikit/ButtonGroup/ButtonGroup';
import s from './FooterDialog.module.scss';

export interface DialogDefaultControlsProps {
  cancelButtonLabel?: string;
  actionButtonLabel?: string;
  isActionDisabled?: boolean;
  onAction?: () => void;
  onCancel?: () => void;
}

const FooterDialogDefaultControls: React.FC<DialogDefaultControlsProps> = ({
  actionButtonLabel = 'Create',
  onAction,
  cancelButtonLabel = 'Cancel',
  onCancel,
  isActionDisabled = false,
}) => {
  return (
    <ButtonGroup className={s.dialog__defaultControls} data-qa="footer-dialog-control">
      <Button variant="secondary" onClick={onCancel} tabIndex={1} data-qa="btn-reject">
        {cancelButtonLabel}
      </Button>
      <Button disabled={isActionDisabled} onClick={onAction} data-qa="btn-accept">
        {actionButtonLabel}
      </Button>
    </ButtonGroup>
  );
};
export default FooterDialogDefaultControls;
