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
package org.smartdata.test.util;

import lombok.extern.slf4j.Slf4j;
import org.testng.IAnnotationTransformer;
import org.testng.annotations.ITestAnnotation;
import org.testng.annotations.Ignore;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

@Slf4j
public class RetryAnalyzerAnnotationTransformer implements IAnnotationTransformer {

  @Override
  public void transform(ITestAnnotation annotation,
                        Class testClass,
                        Constructor testConstructor,
                        Method testMethod) {
    if (shouldSkipRetryConfiguration(testClass, testMethod)) {
      annotation.setEnabled(false);
      return;
    }
    annotation.setRetryAnalyzer(RetryAnalyzer.class);
  }

  private boolean shouldSkipRetryConfiguration(Class<?> testClass, Method testMethod) {
    if (testMethod != null && testMethod.isAnnotationPresent(Ignore.class)) {
      log.info("Skipping retry for @Ignore method: {}", testMethod.getName());
      return true;
    }
    if (testClass != null && testClass.isAnnotationPresent(Ignore.class)) {
      log.info("Skipping retry for @Ignore class: {}", testClass.getSimpleName());
      return true;
    }
    return false;
  }
}
