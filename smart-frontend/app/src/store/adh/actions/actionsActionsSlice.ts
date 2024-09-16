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
import type { AdhAction } from '@models/adh';
import type { ModalState } from '@models/modal';
import { createAsyncThunk } from '@store/redux';
import { getActions } from './actionsSlice';
import { showError, showSuccess } from '@store/notificationsSlice';
import { getErrorMessage } from '@utils/responseUtils';
import type { RequestError } from '@api';
import { AdhActionsApi } from '@api';

const createAction = createAsyncThunk('adh/actionsActions/createAction', async (text: string, thunkAPI) => {
  thunkAPI.dispatch(setIsActionInProgress(true));
  try {
    await AdhActionsApi.createAction(text);
    thunkAPI.dispatch(showSuccess({ message: 'New action was performed successfully' }));
    thunkAPI.dispatch(closeCreateActionDialog());
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  } finally {
    thunkAPI.dispatch(setIsActionInProgress(false));
  }
});

const repeatAction = createAsyncThunk('adh/actionsActions/repeatAction', async (text: string, thunkAPI) => {
  thunkAPI.dispatch(setIsActionInProgress(true));
  try {
    // in really, repeat action is recreate new action
    await AdhActionsApi.createAction(text);
    thunkAPI.dispatch(showSuccess({ message: 'Action was repeated successfully' }));
    thunkAPI.dispatch(closeUpdateActionDialog());
  } catch (error) {
    thunkAPI.dispatch(showError({ message: getErrorMessage(error as RequestError) }));
    return thunkAPI.rejectWithValue(error);
  } finally {
    thunkAPI.dispatch(setIsActionInProgress(false));
  }
});

const withUpdate = (name: string, dialogAction: ReturnType<typeof createAsyncThunk>) => {
  return createAsyncThunk(name, async (payload: unknown, thunkAPI) => {
    await thunkAPI.dispatch(dialogAction(payload)).unwrap();
    await thunkAPI.dispatch(getActions());
  });
};

const createActionWithUpdate = withUpdate(
  'adh/actionsActions/createActionWithUpdate',
  createAction as ReturnType<typeof createAsyncThunk>,
);

const repeatActionWithUpdate = withUpdate(
  'adh/actionsActions/repeatActionWithUpdate',
  repeatAction as ReturnType<typeof createAsyncThunk>,
);

type AdhActionsActions = ModalState<AdhAction, 'action'>;

const createInitialState = (): AdhActionsActions => ({
  createDialog: {
    isOpen: false,
  },
  deleteDialog: {
    action: null,
  },
  updateDialog: {
    action: null,
  },
  isActionInProgress: false,
});

const actionsActionsSlice = createCrudSlice({
  name: 'adh/actionsActions',
  entityName: 'action',
  createInitialState,
  reducers: {},
  extraReducers: () => {},
});

const {
  openCreateDialog: openCreateActionDialog,
  openUpdateDialog: openUpdateActionDialog,
  closeCreateDialog: closeCreateActionDialog,
  closeUpdateDialog: closeUpdateActionDialog,
  setIsActionInProgress,
} = actionsActionsSlice.actions;

export {
  openCreateActionDialog,
  openUpdateActionDialog,
  closeCreateActionDialog,
  closeUpdateActionDialog,
  createActionWithUpdate,
  repeatActionWithUpdate,
};

export default actionsActionsSlice.reducer;
