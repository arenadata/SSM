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
import React, { useMemo } from 'react';
import cn from 'classnames';
import s from './PaginationButtons.module.scss';
import Icon from '@uikit/Icon/Icon';
import Button from '@uikit/Button/Button';

export type PaginationBtnArrowVariant = 'arrowSingle' | 'arrowDouble';
export type PaginationBtnVariant = 'next' | 'prev';

interface PaginationButtonProps {
  arrowVariant: PaginationBtnArrowVariant;
  onClick: () => void;
  disabled?: boolean;
  variant?: PaginationBtnVariant;
  dataTest?: string;
}

const getArrowIconName = (arrowVariant: PaginationBtnArrowVariant) =>
  arrowVariant === 'arrowSingle' ? 'chevron' : 'chevron-double';
const getArrowSize = (arrowVariant: PaginationBtnArrowVariant) => (arrowVariant === 'arrowSingle' ? 11 : 20);

const PaginationStepButton = ({
  arrowVariant,
  onClick,
  disabled = false,
  variant = 'prev',
  dataTest = 'pagination-step-button',
}: PaginationButtonProps) => {
  const btnClasses = useMemo(
    () =>
      cn({
        [s[`paginationButtonArrowSingle_${variant}`]]: arrowVariant === 'arrowSingle',
        [s[`paginationButtonArrowDouble_${variant}`]]: arrowVariant === 'arrowDouble',
      }),
    [variant, arrowVariant],
  );

  return (
    <Button variant="tertiary" onClick={onClick} className={btnClasses} disabled={disabled} data-test={dataTest}>
      <Icon size={getArrowSize(arrowVariant)} name={getArrowIconName(arrowVariant)} />
    </Button>
  );
};

export default PaginationStepButton;
