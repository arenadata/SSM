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
import type { To } from 'react-router-dom';
import { NavLink } from 'react-router-dom';
import type { IconsNames } from '@uikit';
import { Icon } from '@uikit';
import s from './LeftBarMenu.module.scss';

type LeftBarMenuItemProps = {
  icon: IconsNames;
  label?: React.ReactNode;
} & (
  | {
      to?: To;
      onClick?: never;
    }
  | {
      to?: never;
      onClick?: () => void;
    }
);

const LeftBarMenuItem: React.FC<LeftBarMenuItemProps> = ({ icon, label, to, onClick }) => {
  const itemContent = (
    <>
      <Icon name={icon} size={20} />
      <span className={s.leftBarMenuItem__label}>{label}</span>
    </>
  );

  if (to) {
    const target = typeof to === 'string' && to.startsWith('http') ? '_blank' : undefined;

    return (
      <NavLink to={to} className={s.leftBarMenuItem} target={target}>
        {itemContent}
      </NavLink>
    );
  }

  return (
    <button className={s.leftBarMenuItem} onClick={onClick}>
      {itemContent}
    </button>
  );
};

export default LeftBarMenuItem;
