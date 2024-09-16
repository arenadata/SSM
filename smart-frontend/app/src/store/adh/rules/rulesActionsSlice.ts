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
import { createCrudSlice } from '@store/redux/createCrudSlice';
import type { AdhRule } from '@models/adh';
import type { ModalState } from '@models/modal';
import { createAsyncThunk } from '@store/redux';
// eslint-disable-next-line import/no-cycle
import { getRules, getRulesMetaInfo } from './rulesSlice';
import { showError, showSuccess } from '@store/notificationsSlice';
import { getErrorMessage } from '@utils/responseUtils';
import type { RequestError } from '@api';
import { AdhRulesApi } from '@api';
import type { PayloadAction } from '@reduxjs/toolkit';

const createRule = createAsyncThunk('adh/rulesActions/createRule', async (text: string, thunkAPI) => {
  thunkAPI.dispatch(setIsActionInProgress(true));
  try {
    await AdhRulesApi.createRule(text);
    thunkAPI.dispatch(closeCreateRuleDialog());
    thunkAPI.dispatch(showSuccess({ message: 'New rule was created and applied successfully' }));
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  } finally {
    thunkAPI.dispatch(setIsActionInProgress(false));
  }
});

const deleteRule = createAsyncThunk('adh/rulesActions/deleteRule', async (ruleId: number, thunkAPI) => {
  thunkAPI.dispatch(setIsActionInProgress(true));
  thunkAPI.dispatch(closeDeleteRuleDialog());
  try {
    await AdhRulesApi.deleteRule(ruleId);
    thunkAPI.dispatch(showSuccess({ message: `Rule #${ruleId} was deleted` }));
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  } finally {
    thunkAPI.dispatch(setIsActionInProgress(false));
  }
});

const startRule = createAsyncThunk('adh/rulesActions/startRule', async (ruleId: number, thunkAPI) => {
  thunkAPI.dispatch(closeStartRuleDialog());
  try {
    await AdhRulesApi.startRule(ruleId);
    thunkAPI.dispatch(showSuccess({ message: `Rule #${ruleId} was started successfully` }));
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  }
});

const stopRule = createAsyncThunk('adh/rulesActions/stopRule', async (ruleId: number, thunkAPI) => {
  thunkAPI.dispatch(closeStopRuleDialog());
  try {
    await AdhRulesApi.stopRule(ruleId);
    thunkAPI.dispatch(showSuccess({ message: `Rule #${ruleId} was stopped successfully` }));
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  }
});

type DialogActionType = ReturnType<typeof createAsyncThunk>;

const withFullUpdate = (name: string, dialogAction: DialogActionType) => {
  return createAsyncThunk(name, async (payload: unknown, thunkAPI) => {
    await thunkAPI.dispatch(dialogAction(payload)).unwrap();
    thunkAPI.dispatch(getRulesMetaInfo());
    thunkAPI.dispatch(getRules());
  });
};

const withMetaInfoUpdate = (name: string, dialogAction: DialogActionType) => {
  return createAsyncThunk(name, async (payload: unknown, thunkAPI) => {
    await thunkAPI.dispatch(dialogAction(payload)).unwrap();
    thunkAPI.dispatch(getRulesMetaInfo());
  });
};

const createRuleWithUpdate = withFullUpdate('adh/rulesActions/createRuleWithUpdate', createRule as DialogActionType);

const deleteRuleWithUpdate = withFullUpdate('adh/rulesActions/deleteRuleWithUpdate', deleteRule as DialogActionType);

const startRuleWithUpdate = withMetaInfoUpdate('adh/rulesActions/startRuleWithUpdate', startRule as DialogActionType);

const stopRuleWithUpdate = withMetaInfoUpdate('adh/rulesActions/stopRuleWithUpdate', stopRule as DialogActionType);

interface AdhRulesActions extends ModalState<AdhRule, 'rule'> {
  startDialog: {
    rule: AdhRule | null;
  };
  stopDialog: {
    rule: AdhRule | null;
  };
}

const createInitialState = (): AdhRulesActions => ({
  createDialog: {
    isOpen: false,
  },
  deleteDialog: {
    rule: null,
  },
  updateDialog: {
    rule: null,
  },
  startDialog: {
    rule: null,
  },
  stopDialog: {
    rule: null,
  },
  isActionInProgress: false,
});

const rulesActionsSlice = createCrudSlice({
  name: 'adh/rulesActions',
  entityName: 'rule',
  createInitialState,
  reducers: {
    openStartRuleDialog(state, action: PayloadAction<AdhRule>) {
      state.startDialog.rule = action.payload;
    },
    openStopRuleDialog(state, action: PayloadAction<AdhRule>) {
      state.stopDialog.rule = action.payload;
    },
    closeStartRuleDialog(state) {
      state.startDialog.rule = null;
    },
    closeStopRuleDialog(state) {
      state.stopDialog.rule = null;
    },
  },
  extraReducers: () => {},
});

const {
  openCreateDialog: openCreateRuleDialog,
  openUpdateDialog: openUpdateRuleDialog,
  openDeleteDialog: openDeleteRuleDialog,
  closeCreateDialog: closeCreateRuleDialog,
  closeUpdateDialog: closeUpdateRuleDialog,
  closeDeleteDialog: closeDeleteRuleDialog,
  setIsActionInProgress,
  openStartRuleDialog,
  openStopRuleDialog,
  closeStartRuleDialog,
  closeStopRuleDialog,
} = rulesActionsSlice.actions;

export {
  openCreateRuleDialog,
  openUpdateRuleDialog,
  openDeleteRuleDialog,
  closeCreateRuleDialog,
  closeUpdateRuleDialog,
  closeDeleteRuleDialog,
  openStartRuleDialog,
  openStopRuleDialog,
  closeStartRuleDialog,
  closeStopRuleDialog,
  createRuleWithUpdate,
  deleteRuleWithUpdate,
  startRuleWithUpdate,
  stopRuleWithUpdate,
};

export default rulesActionsSlice.reducer;
