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
import { FlexGroup, IconButton } from '@uikit';
import TableCell from '@uikit/Table/TableCell/TableCell';
import { useDispatch } from '@hooks';
import type { AdhAction } from '@models/adh';
import { openUpdateActionDialog } from '@store/adh/actions/actionsActionsSlice';

interface ActionActionsCellProps {
  action: AdhAction;
}

const ActionActionsCell: React.FC<ActionActionsCellProps> = ({ action }) => {
  const dispatch = useDispatch();

  const handleReset = () => {
    dispatch(openUpdateActionDialog(action));
  };

  return (
    <TableCell align="center" data-qa="actions">
      <FlexGroup gap="4px">
        <IconButton icon="refresh" title="Repeat action" onClick={handleReset} data-qa="action-refresh" />
      </FlexGroup>
    </TableCell>
  );
};

export default ActionActionsCell;
