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
import { AdhAuditEventResult, AdhAuditObjectType, AdhAuditOperation } from '@models/adh';
import type { AdhAuditEvent, AdhAuditEventsFilter } from '@models/adh';
import { getOptionsFromEnum } from '@uikit/Select/Select.utils';
import AuditEventResult from './AuditEventResultCell/AuditEventResult';

const auditEventObjectTypeOptions = getOptionsFromEnum(AdhAuditObjectType);
const auditEventOperationsOptions = getOptionsFromEnum(AdhAuditOperation);
const adhAuditEventResultOptions = getOptionsFromEnum(AdhAuditEventResult);

export const auditEventsColumns: TableColumnSchema[] = [
  {
    name: 'id',
    label: 'ID',
    isSortable: true,
  },
  {
    name: 'username',
    label: 'User',
    isSortable: true,
    filterRenderer: () => {
      return <TableSearchFilter<AdhAuditEventsFilter> filterName="usernameLike" placeholder="Search text like" />;
    },
    filterName: 'usernameLike',
  },
  {
    name: 'timestamp',
    label: 'Date',
    isSortable: true,
    filterRenderer: (closeFilter) => {
      return <TableDateRangePickerFilter<AdhAuditEventsFilter> filterName="eventTime" closeFilter={closeFilter} />;
    },
    filterName: 'eventTime',
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'objectType',
    label: 'Object Type',
    isSortable: true,
    filterRenderer: () => {
      return (
        <TableMultiSelectFilter<AdhAuditEventsFilter, AdhAuditObjectType>
          filterName="objectTypes"
          options={auditEventObjectTypeOptions}
        />
      );
    },
    filterName: 'objectTypes',
    schema: {
      type: SchemaColumnType.StatusText,
    },
  },
  {
    name: 'objectId',
    label: 'Object ID',
    isSortable: true,
  },
  {
    name: 'operation',
    label: 'Operation',
    isSortable: true,
    filterRenderer: () => {
      return (
        <TableMultiSelectFilter<AdhAuditEventsFilter, AdhAuditOperation>
          filterName="operations"
          options={auditEventOperationsOptions}
        />
      );
    },
    filterName: 'operations',
    schema: {
      type: SchemaColumnType.StatusText,
    },
  },
  {
    name: 'result',
    label: 'Result',
    filterRenderer: () => {
      return (
        <TableMultiSelectFilter<AdhAuditEventsFilter, AdhAuditEventResult>
          filterName="results"
          options={adhAuditEventResultOptions}
        />
      );
    },
    filterName: 'results',
    schema: {
      cellRenderer: (auditEvent: AdhAuditEvent) => <AuditEventResult auditEvent={auditEvent} />,
    },
  },
];
