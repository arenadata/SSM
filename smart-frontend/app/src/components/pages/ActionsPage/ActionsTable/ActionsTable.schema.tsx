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
import { TableDateRangePickerFilter, TableMultiSelectFilter, TableSearchFilter } from '@uikit/Table/TableFilter';
import { AdhActionSource, AdhActionState } from '@models/adh';
import type { AdhActionsFilter, AdhAction } from '@models/adh';
import { getOptionsFromEnum } from '@uikit/Select/Select.utils';
import ActionActionsCell from './ActionActionsCell/ActionActionsCell';
import ActionStatusCell from './ActionStatusCell/ActionStatusCell';
import ActionSourceCell from './ActionSourceCell/ActionSourceCell';
import ActionsHostsFilter from '@pages/ActionsPage/ActionsTable/ActionsHostsFilter/ActionsHostsFilter';

const actionStatesOptions = getOptionsFromEnum(AdhActionState);
const actionSourcesOptions = [
  {
    label: 'Rule action',
    value: AdhActionSource.Rule,
  },
  {
    label: 'User action',
    value: AdhActionSource.User,
  },
];

export const actionsColumns: TableColumnSchema[] = [
  {
    name: 'id',
    label: 'ID',
    isSortable: true,
  },
  {
    name: 'textRepresentation',
    label: 'Action',
    filterRenderer: () => {
      return <TableSearchFilter<AdhActionsFilter> filterName="textRepresentationLike" placeholder="Search text like" />;
    },
    filterName: 'textRepresentationLike',
    schema: {
      type: SchemaColumnType.BigText,
    },
  },
  {
    name: 'execHost',
    label: 'Host',
    isSortable: true,
    filterRenderer: () => {
      return <ActionsHostsFilter />;
    },
    filterName: 'hosts',
  },
  {
    name: 'submissionTime',
    label: 'Create Time',
    isSortable: true,
    filterRenderer: (closeFilter) => {
      return <TableDateRangePickerFilter<AdhActionsFilter> filterName="submissionTime" closeFilter={closeFilter} />;
    },
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'completionTime',
    label: 'Finish Time',
    isSortable: true,
    filterRenderer: (closeFilter) => {
      return <TableDateRangePickerFilter<AdhActionsFilter> filterName="completionTime" closeFilter={closeFilter} />;
    },
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'state',
    label: 'Status',
    isSortable: true,
    width: '150px',
    filterRenderer: () => {
      return (
        <TableMultiSelectFilter<AdhActionsFilter, AdhActionState> filterName="states" options={actionStatesOptions} />
      );
    },
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
    isSortable: true,
    width: '150px',
    filterRenderer: () => {
      return <TableMultiSelectFilter<AdhActionsFilter, string> filterName="sources" options={actionSourcesOptions} />;
    },
    filterName: 'sources',
    schema: {
      cellRenderer: (action: AdhAction) => {
        return <ActionSourceCell action={action} />;
      },
    },
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
