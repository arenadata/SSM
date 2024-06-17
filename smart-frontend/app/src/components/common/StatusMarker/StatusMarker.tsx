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
import type { Status } from './StatusMarker.types';
import cn from 'classnames';
import s from './StatusMarker.module.scss';

interface StatusMarkerProps extends React.HTMLAttributes<HTMLDivElement> {
  status: Status;
}

const StatusMarker: React.FC<StatusMarkerProps> = ({ status, className, ...props }) => {
  const classes = cn(className, s.statusMarker, s[`statusMarker_${status}`]);
  return <div className={classes} {...props}></div>;
};

export default StatusMarker;
