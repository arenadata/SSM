package org.smartdata.test.service;

import io.arenadata.test.model.Component;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.model.SsmComponent;
import org.springframework.core.convert.converter.Converter;

@Slf4j
public class SsmComponentConverter implements Converter<String, Component> {

    @Override
    public Component convert(String value) {
        return SsmComponent.fromName(value);
    }
}
