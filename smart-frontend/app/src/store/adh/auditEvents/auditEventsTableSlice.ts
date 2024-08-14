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
import type { TableState } from '@models/table';
import { createTableSlice } from '@store/redux';
import type { AdhAuditEventsFilter } from '@models/adh';
import { defaultAuditFrequency } from '@constants';

type AdhTablesTableState = TableState<AdhAuditEventsFilter>;

const createInitialState = (): AdhTablesTableState => ({
  filter: {
    usernameLike: undefined,
    eventTime: undefined,
    objectTypes: undefined,
    objectIds: undefined,
    operations: undefined,
    results: undefined,
  },
  paginationParams: {
    perPage: 10,
    pageNumber: 0,
  },
  requestFrequency: defaultAuditFrequency,
  sortParams: {
    sortBy: 'id',
    sortDirection: 'desc',
  },
});

const auditEventsTableSlice = createTableSlice({
  name: 'adh/auditEventsTable',
  createInitialState,
  reducers: {},
  extraReducers: () => {},
});

const {
  //
  setPaginationParams: setAuditEventsPaginationParams,
  cleanupTable: cleanupAuditEventsTable,
  setSortParams: setAuditEventsSortParams,
  setFilter: setAuditEventsFilter,
  resetFilter: resetAuditEventsFilter,
  setRequestFrequency,
} = auditEventsTableSlice.actions;

export {
  //
  setAuditEventsPaginationParams,
  cleanupAuditEventsTable,
  setAuditEventsSortParams,
  setAuditEventsFilter,
  resetAuditEventsFilter,
  setRequestFrequency,
};
export default auditEventsTableSlice.reducer;
