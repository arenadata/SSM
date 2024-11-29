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
import { useDebounce, useDispatch, useRequestTimer, useStore } from '@hooks';
import { useEffect, useMemo } from 'react';
import { cleanupActions as cleanupActionDialogs } from '@store/adh/actionDialogs/actionsActionsSlice';
import { defaultDebounceDelay, defaultActionPageFrequency } from '@constants';
import { cleanupAction, getAction, refreshAction } from '@store/adh/action/actionSlice';
import { useParams } from 'react-router-dom';
import { AdhActionState } from '@models/adh';

export const useRequestAction = () => {
  const { actionId = '' } = useParams();
  const action = useStore((s) => s.adh.action.action);
  const isSomeError = useStore((s) => s.adh.action.isSomeError);

  const isNeedUpdate = useMemo(() => {
    return (!action && !isSomeError) || action?.state === AdhActionState.Running;
  }, [action, isSomeError]);

  const dispatch = useDispatch();

  useEffect(() => {
    if (!actionId) return;
    dispatch(getAction(parseInt(actionId)));

    return () => {
      dispatch(cleanupAction());
      dispatch(cleanupActionDialogs());
    };
  }, [dispatch, actionId]);

  const debounceGetData = useDebounce(() => {
    dispatch(getAction(parseInt(actionId)));
  }, defaultDebounceDelay);

  const debounceRefreshData = useDebounce(() => {
    dispatch(refreshAction(parseInt(actionId)));
  }, defaultDebounceDelay);

  useRequestTimer(debounceGetData, debounceRefreshData, defaultActionPageFrequency, isNeedUpdate, [actionId]);
};
