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
package org.smartdata.server.engine;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.SmartContext;
import org.smartdata.hdfs.scheduler.ActionSchedulerService;
import org.smartdata.metastore.MetaStore;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class AbstractServiceFactory {

  public static List<ActionSchedulerService> createSchedulerServices(
      List<Class<? extends ActionSchedulerService>> classes,
      ServerContext context,
      MetaStore metaStore) {
    List<ActionSchedulerService> services = new ArrayList<>();
    for (Class<? extends ActionSchedulerService> clazz : classes) {
      try {
        ActionSchedulerService service =
            clazz.getConstructor(SmartContext.class, MetaStore.class)
                .newInstance(context, metaStore);
        services.add(service);
      } catch (IllegalAccessException
               | InstantiationException | NoSuchMethodException
               | InvocationTargetException | NullPointerException e) {
        log.warn("Error while create action scheduler service '" + clazz.getName() + "'.", e);
      }
    }
    return services;
  }
}
