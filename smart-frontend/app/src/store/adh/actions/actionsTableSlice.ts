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
import { createAsyncThunk, createTableSlice } from '@store/redux';
import type { AdhActionsFilter, AdhClusterNode } from '@models/adh';
import { AdhClusterInfoApi, type RequestError } from '@api';
import { showError } from '@store/notificationsSlice';
import { getErrorMessage } from '@utils/responseUtils';
import { defaultActionsFrequency } from '@constants';

export const loadHosts = createAsyncThunk('adh/actionsTable/loadHosts', async (_, thunkAPI) => {
  try {
    const collection = await AdhClusterInfoApi.getNodes({});

    return collection;
  } catch (error) {
    thunkAPI.dispatch(
      showError({
        message: getErrorMessage(error as RequestError),
      }),
    );
    return thunkAPI.rejectWithValue(error);
  }
});

type AdhTablesTableState = TableState<AdhActionsFilter> & {
  relatedData: {
    hosts: AdhClusterNode[];
    isHostsLoaded: boolean;
  };
};

const createInitialState = (): AdhTablesTableState => ({
  filter: {
    textRepresentationLike: undefined,
    submissionTime: undefined,
    hosts: undefined,
    states: undefined,
    sources: undefined,
    completionTime: undefined,
  },
  paginationParams: {
    perPage: 10,
    pageNumber: 0,
  },
  requestFrequency: defaultActionsFrequency,
  sortParams: {
    sortBy: 'id',
    sortDirection: 'desc',
  },
  relatedData: {
    hosts: [],
    isHostsLoaded: false,
  },
});

const actionsTableSlice = createTableSlice({
  name: 'adh/actionsTable',
  createInitialState,
  reducers: {},
  extraReducers: (builder) => {
    builder.addCase(loadHosts.fulfilled, (state, action) => {
      state.relatedData.hosts = action.payload.items;
      state.relatedData.isHostsLoaded = true;
    });
    builder.addCase(loadHosts.rejected, (state) => {
      state.relatedData.hosts = [];
      state.relatedData.isHostsLoaded = true;
    });
  },
});

const {
  //
  setPaginationParams: setActionsPaginationParams,
  cleanupTable: cleanupActionsTable,
  setSortParams: setActionsSortParams,
  setFilter: setActionsFilter,
  resetFilter: resetActionsFilter,
  setRequestFrequency,
} = actionsTableSlice.actions;

export {
  //
  setActionsPaginationParams,
  cleanupActionsTable,
  setActionsSortParams,
  setActionsFilter,
  resetActionsFilter,
  setRequestFrequency,
};
export default actionsTableSlice.reducer;
