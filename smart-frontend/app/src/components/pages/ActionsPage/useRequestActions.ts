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
import { useEffect } from 'react';
import { cleanupActions, getActions, refreshActions } from '@store/adh/actions/actionsSlice';
import { cleanupActionsTable, loadHosts } from '@store/adh/actions/actionsTableSlice';
import { defaultDebounceDelay } from '@constants';

export const useRequestActions = () => {
  const dispatch = useDispatch();

  const paginationParams = useStore(({ adh }) => adh.actionsTable.paginationParams);
  const sortParams = useStore(({ adh }) => adh.actionsTable.sortParams);
  const filter = useStore(({ adh }) => adh.actionsTable.filter);
  const requestFrequency = useStore(({ adh }) => adh.actionsTable.requestFrequency);

  useEffect(() => {
    dispatch(loadHosts());
    return () => {
      dispatch(cleanupActions());
      dispatch(cleanupActionsTable());
    };
  }, [dispatch]);

  const debounceGetData = useDebounce(() => {
    dispatch(getActions());
  }, defaultDebounceDelay);

  const debounceRefreshData = useDebounce(() => {
    dispatch(refreshActions());
  }, defaultDebounceDelay);

  useRequestTimer(debounceGetData, debounceRefreshData, requestFrequency, true, [
    filter,
    sortParams,
    paginationParams,
    requestFrequency,
  ]);
};
