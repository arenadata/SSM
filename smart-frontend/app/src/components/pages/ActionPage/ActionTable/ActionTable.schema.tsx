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
import type { TableColumnSchema } from '@uikit/Table/Table.types';
import { SchemaColumnType } from '@uikit/Table/Table.types';
import type { AdhAction } from '@models/adh';
import ActionActionsCell from '@commonComponents/Action/ActionTableComponents/Cells/ActionActionsCell/ActionActionsCell';
import ActionStatusCell from '@commonComponents/Action/ActionTableComponents/Cells/ActionStatusCell/ActionStatusCell';
import ActionSourceCell from '@commonComponents/Action/ActionTableComponents/Cells/ActionSourceCell/ActionSourceCell';
import PassedTimeCell from '@uikit/Table/TableCell/AdvancedCells/PassedTimeCell';

export const actionColumns: TableColumnSchema[] = [
  {
    name: 'id',
    label: 'ID',
  },
  {
    name: 'submissionTime',
    label: 'Create Time',
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'completionTime',
    label: 'Finish Time',
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'runningTime',
    label: 'Running time',
    schema: {
      cellRenderer: (action: AdhAction) => (
        <PassedTimeCell startTime={action.submissionTime} finishTime={action.completionTime} />
      ),
    },
  },
  {
    name: 'state',
    label: 'Status',
    width: '150px',
    filterName: 'states',
    schema: {
      cellRenderer: (action: AdhAction) => {
        return <ActionStatusCell action={action} />;
      },
    },
  },
  {
    name: 'source',
    label: 'Type',
    width: '150px',
    filterName: 'sources',
    schema: {
      cellRenderer: (action: AdhAction) => {
        return <ActionSourceCell action={action} />;
      },
    },
  },
  {
    name: 'execHost',
    label: 'Host',
    filterName: 'hosts',
  },
  {
    name: 'actions',
    label: 'Actions',
    headerAlign: 'center',
    width: '120px',
    schema: {
      cellRenderer: (action: AdhAction) => <ActionActionsCell action={action} />,
    },
  },
];
