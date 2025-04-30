package org.smartdata.test.suite;

import io.arenadata.test.suite.BaseSuite;
import io.qameta.allure.aspects.StepsAspects;
import org.smartdata.test.SsmQaApp;
import org.smartdata.test.configuration.SsmTestConfiguration;
import org.smartdata.test.configuration.SsmWebConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(StepsAspects.class)
@SpringBootTest(classes = {SsmQaApp.class})
public abstract class SsmBaseSuite extends BaseSuite {

    @Autowired
    protected SsmTestConfiguration testConfig;

    @Autowired
    protected SsmWebConfiguration webConfig;
}
