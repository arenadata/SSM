/**
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
package org.smartdata.hdfs.impersonation;

import org.apache.hadoop.security.UserGroupInformation;

import java.io.IOException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;

public abstract class BaseUserImpersonationStrategy implements UserImpersonationStrategy {
  protected UserGroupInformation createProxyUser(String user) {
    try {
      return UserGroupInformation.createProxyUser(
          user, UserGroupInformation.getCurrentUser());
    } catch (IOException exception) {
      throw new IllegalStateException("Error getting current user", exception);
    }
  }

  @Override
  public <T> T runWithImpersonation(String currentUser, PrivilegedExceptionAction<T> action) throws Exception {
    return getProxyUserFor(currentUser).doAs(action);
  }

  @Override
  public void runWithImpersonation(String currentUser, Runnable action) {
    getProxyUserFor(currentUser).doAs((PrivilegedAction<Void>) () -> {
      action.run();
      return null;
    });
  }

  protected abstract UserGroupInformation getProxyUserFor(String user);
}
