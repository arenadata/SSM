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
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useStore } from '@hooks';
import { AUTH_STATE } from '@store/authSlice';

const PrivateResource: React.FC<React.PropsWithChildren> = ({ children }) => {
  const needCheckSession = useStore((s) => s.auth.needCheckSession);
  const authState = useStore((s) => s.auth.authState);
  const location = useLocation();

  if (needCheckSession) {
    return null;
  }

  if (authState === AUTH_STATE.NotAuth) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export default PrivateResource;
