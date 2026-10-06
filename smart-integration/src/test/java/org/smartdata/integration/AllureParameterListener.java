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
package org.smartdata.integration;

import io.qameta.allure.Allure;
import org.junit.runner.Description;
import org.junit.runner.notification.RunListener;

/**
 * Exposes the JUnit4 Parameterized runner name suffix as an Allure result
 * parameter, since allure-junit4 doesn't extract parameters on its own.
 * This allows Allure TestOps to distinguish parameterized invocations
 * instead of treating them as retries of the same test case.
 * Must be registered after {@link io.qameta.allure.junit4.AllureJunit4}.
 */
public class AllureParameterListener extends RunListener {

  @Override
  public void testStarted(Description description) {
    String methodName = description.getMethodName();
    int paramsStart = methodName == null ? -1 : methodName.indexOf('[');
    if (paramsStart == -1 || !methodName.endsWith("]")) {
      return;
    }

    Allure.parameter("params",
        methodName.substring(paramsStart + 1, methodName.length() - 1));
  }
}
