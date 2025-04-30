package org.smartdata.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(scanBasePackages = {"org.smartdata.test"}, exclude = {DataSourceAutoConfiguration.class})
public class SsmQaApp {

    public static void main(String[] args) {
        SpringApplication.run(SsmQaApp.class, args);
    }
}
