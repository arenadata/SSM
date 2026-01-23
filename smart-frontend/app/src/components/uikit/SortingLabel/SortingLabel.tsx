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
import type { SortingProps, SortParams } from '@models/table';
import Icon from '@uikit/Icon/Icon';
import s from './SortingLabel.module.scss';

interface SortingLabelProps extends Partial<SortingProps> {
  children: React.ReactNode;
  name: string;
  isSorted?: boolean;
}

const revertOrder = (order: SortParams['sortDirection']) => (order === 'asc' ? 'desc' : 'asc');

const SortingLabel: React.FC<SortingLabelProps> = ({ children, onSorting, name, sortParams }) => {
  const isSorted = name === sortParams?.sortBy;

  const wrapClasses = cn(s.sortingLabel, {
    'is-sorted': isSorted,
  });

  const arrowClasses = cn(
    s.sortingLabel__arrow,
    s[`sortingLabel__arrow_${(isSorted ? sortParams?.sortDirection : undefined) ?? 'asc'}`],
  );

  const handleClick = () => {
    const newSortDirection = isSorted ? revertOrder(sortParams.sortDirection) : 'asc';
    onSorting?.({ sortBy: name, sortDirection: newSortDirection });
  };

  return (
    <div className={wrapClasses} onClick={handleClick} data-qa="sorting">
      <div className={s.sortingLabel__label}>{children}</div>
      <Icon name="arrow-sorting" size={14} className={arrowClasses} />
    </div>
  );
};

export default SortingLabel;
