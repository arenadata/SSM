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
import { LoadState } from '@models/loadState';
import { createSlice } from '@reduxjs/toolkit';
import { createAsyncThunk } from '@store/redux';
import { showError } from '@store/notificationsSlice';
import { getErrorMessage } from '@utils/responseUtils';
import type { RequestError } from '@api';
import { AdhActionsApi } from '@api';
import { executeWithMinDelay } from '@utils/requestUtils';
import { defaultSpinnerDelay } from '@constants';
import type { AdhActionDetails } from '@models/adh';

interface AdhActionSliceState {
  action: AdhActionDetails | null;
  loadState: LoadState;
  isSomeError: boolean;
}

const loadAction = createAsyncThunk('adh/action/loadAction', async (actionId: number, thunkAPI) => {
  try {
    return await AdhActionsApi.getAction(actionId);
  } catch (error) {
    thunkAPI.dispatch(
      showError({
        message: getErrorMessage(error as RequestError),
      }),
    );
    thunkAPI.dispatch(setIsSomeError(true));
    thunkAPI.dispatch(setActionLoadState(LoadState.Loaded));
    return thunkAPI.rejectWithValue(error);
  }
});

const getAction = createAsyncThunk('adh/action/getAction', async (actionId: number, thunkAPI) => {
  thunkAPI.dispatch(setActionLoadState(LoadState.Loading));
  const startDate = new Date();

  await thunkAPI.dispatch(loadAction(actionId));

  executeWithMinDelay({
    startDate,
    delay: defaultSpinnerDelay,
    callback: () => {
      thunkAPI.dispatch(setActionLoadState(LoadState.Loaded));
    },
  });
});

const refreshAction = createAsyncThunk('adh/action/refreshAction', async (actionId: number, thunkAPI) => {
  thunkAPI.dispatch(loadAction(actionId));
});

const createInitialState = (): AdhActionSliceState => ({
  action: null,
  loadState: LoadState.NotLoaded,
  isSomeError: false,
});

const actionSlice = createSlice({
  name: 'adh/action',
  initialState: createInitialState(),
  reducers: {
    cleanupAction() {
      return createInitialState();
    },
    setLoadState(state, action) {
      state.loadState = action.payload;
    },
    setIsSomeError(state, action) {
      state.isSomeError = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(loadAction.fulfilled, (state, action) => {
      state.action = action.payload;
    });
    builder.addCase(loadAction.rejected, (state) => {
      state.action = null;
    });
  },
});

const { cleanupAction, setLoadState: setActionLoadState, setIsSomeError } = actionSlice.actions;
export { cleanupAction, setActionLoadState, setIsSomeError, getAction, refreshAction };
export default actionSlice.reducer;
