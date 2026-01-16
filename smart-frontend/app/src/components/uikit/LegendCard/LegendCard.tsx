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
import cn from 'classnames';
import Icon from '@uikit/Icon/Icon';
import s from './LegendCard.module.scss';
import type { IconsNames } from '@uikit/Icon/sprite';

interface LegendCardProps {
  title: string;
  count: number;
  icon: IconsNames;
  variant?: 'primary' | 'secondary';
}

const LegendCard: React.FC<LegendCardProps> = ({ title, count = 0, icon, variant = 'primary' }) => {
  const classes = cn(s.legendCard, s[`legendCard_${variant}`]);

  return (
    <div className={classes} data-qa={title}>
      <Icon name={icon} size={32} />
      <div className={s.legendCard__title}>{title}</div>
      <div className={s.legendCard__count}>{count}</div>
    </div>
  );
};

LegendCard.displayName = 'LegendCard';

export default LegendCard;
