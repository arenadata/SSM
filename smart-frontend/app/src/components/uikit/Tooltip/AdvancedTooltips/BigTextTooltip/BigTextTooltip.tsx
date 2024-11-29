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
import s from './BigTextTooltip.module.scss';
import Tooltip, { type TooltipProps } from '../../Tooltip';
import { prepareLabel } from './BigTextTooltip.utils';

interface BigTextTooltipProps extends TooltipProps {
  label: string;
  labelLimit?: number;
}

const BigTextTooltip = ({
  children,
  label,
  labelLimit = Number.POSITIVE_INFINITY,
  ...otherProps
}: BigTextTooltipProps) => {
  const preparedLabel = prepareLabel(label, labelLimit);

  return (
    <Tooltip label={preparedLabel} placement="top-start" className={s.bigTextTooltip} {...otherProps}>
      {children}
    </Tooltip>
  );
};

export default BigTextTooltip;
