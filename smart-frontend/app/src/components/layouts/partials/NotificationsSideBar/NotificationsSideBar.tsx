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
import React, { useEffect } from 'react';
import { useDispatch, useStore } from '@hooks';
import type { Notification } from '@models/notification';
import { NotificationVariant } from '@models/notification';
import ErrorAlert from './Alert/ErrorAlert';
import InfoAlert from './Alert/InfoAlert';
import SuccessAlert from './Alert/SuccessAlert';
import { closeNotification } from '@store/notificationsSlice';
import s from './NotificationsSideBar.module.scss';

const NotificationItem: React.FC<Notification> = (props) => {
  const { ttl, variant, id } = props;
  const dispatch = useDispatch();
  const removeNotification = () => {
    dispatch(closeNotification(id));
  };

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    if (ttl) {
      timer = setTimeout(() => {
        removeNotification();
      }, ttl);
    }

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (variant === NotificationVariant.Error) {
    return <ErrorAlert {...props} onClose={removeNotification} />;
  }
  if (variant === NotificationVariant.Info) {
    return <InfoAlert {...props} onClose={removeNotification} />;
  }
  if (variant === NotificationVariant.Success) {
    return <SuccessAlert {...props} onClose={removeNotification} />;
  }

  return null;
};

const NotificationsSideBar: React.FC = () => {
  const notifications = useStore((s) => s.notifications.notifications);

  return (
    <div className={s.notificationsSideBar} data-qa="notification-container">
      {notifications.map((item) => {
        return <NotificationItem key={item.id} {...item} />;
      })}
    </div>
  );
};
export default NotificationsSideBar;
