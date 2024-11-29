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
import TableCell from '@uikit/Table/TableCell/TableCell';
import type { AdhAction } from '@models/adh';
import CellBigTextWrapper from '@uikit/Table/TableCell/AdvancedCells/CellSubComponents/CellBigTextWrapper/CellBigTextWrapper';
import { Link } from 'react-router-dom';

interface ActionActionTextCellProps {
  action: AdhAction;
}

const ActionActionTextCell = ({ action: { textRepresentation, id } }: ActionActionTextCellProps) => {
  return (
    <TableCell>
      <Link to={`/actions/${id}`} className="text-link">
        <CellBigTextWrapper text={textRepresentation} />
      </Link>
    </TableCell>
  );
};

export default ActionActionTextCell;
