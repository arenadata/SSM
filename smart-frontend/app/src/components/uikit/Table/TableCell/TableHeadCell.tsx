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
import React, { useRef } from 'react';
import type { TableColumnSchema } from '../Table.types';
import type { TableCellProps } from './TableCell';
import TableCell from './TableCell';
import SortingLabel from '@uikit/SortingLabel/SortingLabel';
import { useTableContext } from '../TableContext';
import ConditionalWrapper from '@uikit/ConditionalWrapper/ConditionalWrapper';
import TableFilter from '../TableFilter/TableFilter';
import cn from 'classnames';
import s from '../Table.module.scss';
import { isValidData } from '@utils/checkUtils';

export type TableHeadCellProps = Omit<TableColumnSchema, 'schema'> & Omit<TableCellProps, 'align' | 'tag' | 'children'>;

const TableHeadCell: React.FC<TableHeadCellProps> = ({
  label,
  headerAlign,
  name,
  isSortable = false,
  filterRenderer,
  className,
  subColumns,
  filterName,
  ...props
}) => {
  const ref = useRef(null);
  const { sortParams, onSorting, filter } = useTableContext<Record<string, unknown>>();
  // if a getHasSetFilter is described in the column config then try to use this function, else try to detect by field name
  const hasSetFilter = isValidData(filter?.[filterName ?? name]);
  const thClasses = cn(className, s.tableHeaderCell, {
    [s.tableHeaderCell_hasSetFilter]: hasSetFilter,
    [s.tableHeaderCell_hasSubColumns]: !!subColumns?.length,
  });

  return (
    <TableCell data-qa={name} {...props} align={headerAlign} tag="th" className={thClasses} ref={ref}>
      <ConditionalWrapper
        Component={SortingLabel}
        isWrap={isSortable}
        name={name}
        sortParams={sortParams}
        onSorting={onSorting}
      >
        {label}
      </ConditionalWrapper>
      {filterRenderer && <TableFilter filterRenderer={filterRenderer} hasSetFilter={hasSetFilter} thRef={ref} />}
    </TableCell>
  );
};

export default TableHeadCell;
