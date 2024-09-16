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
import s from './MainLeftSideBar.module.scss';
import LeftBarMenu from '@layouts/partials/LeftBarMenu/LeftBarMenu';
import LeftBarMenuItem from '@layouts/partials/LeftBarMenu/LeftBarMenuItem';
import MainLogo from '@layouts/partials/MainLogo/MainLogo';
import LeftBarLogoutItem from '@layouts/partials/LeftBarMenu/LeftBarLogoutItem';
import LeftBarUserItem from '@layouts/partials/LeftBarMenu/LeftBarUserItem';

const MainLeftSideBar: React.FC = () => {
  return (
    <aside className={s.mainLeftSideBar}>
      <MainLogo height="23px" />
      <LeftBarMenu>
        <LeftBarMenuItem icon="cluster-info" label="Cluster Info" to="/" />
        <LeftBarMenuItem icon="rules" label="Rules" to="/rules" />
        <LeftBarMenuItem icon="actions" label="Actions" to="/actions" />
        <LeftBarMenuItem icon="audit" label="Audit" to="/audit" />
      </LeftBarMenu>

      <LeftBarMenu className={s.mainLeftSideBar__systemMenu}>
        <LeftBarMenuItem
          icon="documentation"
          label="Documentation"
          to="https://docs.arenadata.io/en/ADH/current/concept/ssm/ssm-architecture.html"
        />
        <LeftBarUserItem />
        <LeftBarLogoutItem />
      </LeftBarMenu>
    </aside>
  );
};

export default MainLeftSideBar;
