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
import { AdhRulesApi } from '@api';
import { executeWithMinDelay } from '@utils/requestUtils';
import { defaultSpinnerDelay } from '@constants';
// eslint-disable-next-line import/no-cycle
import { startRuleWithUpdate, stopRuleWithUpdate } from './rulesActionsSlice';
import type { AdhRule } from '@models/adh';
import { AdhRuleState } from '@models/adh';

interface AdhRulesSliceState {
  rules: AdhRule[];
  totalCount: number;
  loadState: LoadState;
  activeCount: number;
  allCount: number;
}

const loadRules = createAsyncThunk('adh/rules/loadRules', async (_, thunkAPI) => {
  const {
    adh: {
      rulesTable: { filter, paginationParams, sortParams },
    },
  } = thunkAPI.getState();

  try {
    const collection = await AdhRulesApi.getRules(filter, sortParams, paginationParams);

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

const getRules = createAsyncThunk('adh/rules/getRules', async (_, thunkAPI) => {
  thunkAPI.dispatch(setRulesLoadState(LoadState.Loading));
  const startDate = new Date();

  await thunkAPI.dispatch(loadRules());

  executeWithMinDelay({
    startDate,
    delay: defaultSpinnerDelay,
    callback: () => {
      thunkAPI.dispatch(setRulesLoadState(LoadState.Loaded));
    },
  });
});

const refreshRules = createAsyncThunk('adh/rules/refreshRules', async (_, thunkAPI) => {
  thunkAPI.dispatch(loadRules());
});

const getRulesMetaInfo = createAsyncThunk('adh/rules/getRulesMetaInfo', async (_, thunkAPI) => {
  try {
    const [
      //
      allCollection,
      activeCollection,
    ] = await Promise.all([
      //
      AdhRulesApi.getRules({}),
      AdhRulesApi.getRules({ ruleStates: [AdhRuleState.Active] }),
    ]);

    return {
      allCollection,
      activeCollection,
    };
  } catch (error) {
    thunkAPI.dispatch(
      showError({
        message: getErrorMessage(error as RequestError),
      }),
    );
    return thunkAPI.rejectWithValue(error);
  }
});

const createInitialState = (): AdhRulesSliceState => ({
  rules: [],
  totalCount: 0,
  loadState: LoadState.NotLoaded,
  activeCount: 0,
  allCount: 0,
});

const rulesSlice = createSlice({
  name: 'adh/rules',
  initialState: createInitialState(),
  reducers: {
    cleanupRules() {
      return createInitialState();
    },
    setLoadState(state, action) {
      state.loadState = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(loadRules.fulfilled, (state, action) => {
      state.rules = action.payload.items;
      state.totalCount = action.payload.total;
    });
    builder.addCase(loadRules.rejected, (state) => {
      state.rules = [];
      state.totalCount = 0;
    });
    builder.addCase(startRuleWithUpdate.fulfilled, (state, action) => {
      const ruleId = action.meta.arg;
      const currentRule = state.rules.find((rule) => rule.id === ruleId);
      if (currentRule) {
        currentRule.state = AdhRuleState.Active;
      }
    });
    builder.addCase(stopRuleWithUpdate.fulfilled, (state, action) => {
      const ruleId = action.meta.arg;
      const currentRule = state.rules.find((rule) => rule.id === ruleId);
      if (currentRule) {
        currentRule.state = AdhRuleState.Disabled;
      }
    });
    builder.addCase(getRulesMetaInfo.fulfilled, (state, action) => {
      state.allCount = action.payload.allCollection.total;
      state.activeCount = action.payload.activeCollection.total;
    });
    builder.addCase(getRulesMetaInfo.rejected, (state) => {
      state.allCount = 0;
      state.activeCount = 0;
    });
  },
});

const { cleanupRules, setLoadState: setRulesLoadState } = rulesSlice.actions;
export { cleanupRules, setRulesLoadState, getRules, refreshRules, getRulesMetaInfo };
export default rulesSlice.reducer;
