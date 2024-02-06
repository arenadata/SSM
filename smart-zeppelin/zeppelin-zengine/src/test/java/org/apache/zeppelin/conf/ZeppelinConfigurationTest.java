/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.conf;

import junit.framework.Assert;

import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.zeppelin.conf.ZeppelinConfiguration.ConfVars;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.util.List;


/**
 * Created by joelz on 8/19/15.
 */
public class ZeppelinConfigurationTest {

    @Before
    public void clearSystemVariables() {
        ZeppelinConfiguration.reset();
        System.clearProperty(ConfVars.ZEPPELIN_NOTEBOOK_DIR.getVarName());
    }

    @Test
    public void getAllowedOrigins2Test() throws MalformedURLException, ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("test-zeppelin-site2.xml");
        List<String> origins = conf.getAllowedOrigins();
        Assert.assertEquals(2, origins.size());
        Assert.assertEquals("http://onehost:8080", origins.get(0));
        Assert.assertEquals("http://otherhost.com", origins.get(1));
        ZeppelinConfiguration.reset();
    }

    @Test
    public void getAllowedOrigins1Test() throws MalformedURLException, ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("test-zeppelin-site1.xml");
        List<String> origins = conf.getAllowedOrigins();
        Assert.assertEquals(1, origins.size());
        Assert.assertEquals("http://onehost:8080", origins.get(0));
        ZeppelinConfiguration.reset();
    }

    @Test
    public void getAllowedOriginsNoneTest() throws MalformedURLException, ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("zeppelin-site.xml");
        List<String> origins = conf.getAllowedOrigins();
        Assert.assertEquals(1, origins.size());
        ZeppelinConfiguration.reset();
    }

    @Test
    public void isWindowsPathTestTrue() throws ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("zeppelin-site.xml");
        Boolean isIt = conf.isWindowsPath("c:\\test\\file.txt");
        Assert.assertTrue(isIt);
        ZeppelinConfiguration.reset();
    }

    @Test
    public void isWindowsPathTestFalse() throws ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("zeppelin-site.xml");
        Boolean isIt = conf.isWindowsPath("~/test/file.xml");
        Assert.assertFalse(isIt);
        ZeppelinConfiguration.reset();
    }

    @Test
    public void getNotebookDirTest() throws ConfigurationException {
        ZeppelinConfiguration conf  = ZeppelinConfiguration.create("zeppelin-site.xml");
        String notebookLocation = conf.getNotebookDir();
        Assert.assertEquals("notebook", notebookLocation);
        ZeppelinConfiguration.reset();
    }
    
    @Test
    public void isNotebookPublicTest() throws ConfigurationException {
      ZeppelinConfiguration conf  = ZeppelinConfiguration.create("zeppelin-site.xml");
      boolean isIt = conf.isNotebokPublic();
      assertTrue(isIt);
      ZeppelinConfiguration.reset();
    }
}
