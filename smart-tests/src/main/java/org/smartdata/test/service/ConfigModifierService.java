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
package org.smartdata.test.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Service
public class ConfigModifierService {

    @Value("${docker-compose-service.compose-file-name}")
    private String composeFileName;

    private static final String SSM_METASTORE_CONFIG_DIR = "target/test-classes/env/multihost/ssm-conf";
    private static final String HMS_CONFIG_DIR = "target/test-classes/env/demo-cluster/ssm-conf";
    private static final String BACKUP_SUFFIX = ".backup";

    /**
     * Gets the current value of a property.
     *
     * @param configFileName The name of the config file
     * @param propertyName The property name
     * @return The current value, or null if not found
     * @throws Exception if file operations fail
     */
    public String getProperty(String configFileName, String propertyName) throws Exception {
        Document doc = loadDocument(configFileName);
        Element property = findProperty(doc, propertyName);
        return property != null ? getPropertyValue(property) : null;
    }

    /**
     * Sets a property value in the specified XML configuration file.
     * Creates a backup if it doesn't exist. Updates existing property or creates new one.
     *
     * @param configFileName The name of the config file (e.g., "smart-site-master.xml")
     * @param propertyName The property name (e.g., "smart.cmdlet.executors")
     * @param newValue The new value to set
     * @throws Exception if file operations fail
     */
    public void setProperty(String configFileName, String propertyName, String newValue) throws Exception {
        Path configPath = getConfigPath(configFileName);
        createBackupIfNeeded(configPath);

        Document doc = loadDocument(configFileName);
        Element property = findProperty(doc, propertyName);

        if (property != null) {
            updatePropertyValue(property, newValue);
        } else {
            addNewProperty(doc, propertyName, newValue);
        }

        saveDocument(doc, configPath);
    }

    /**
     * Adds a new property to the configuration file.
     *
     * @param configFileName The name of the config file
     * @param propertyName The property name
     * @param value The property value
     * @throws Exception if file operations fail
     */
    public void addProperty(String configFileName, String propertyName, String value) throws Exception {
        Path configPath = getConfigPath(configFileName);
        createBackupIfNeeded(configPath);

        Document doc = loadDocument(configFileName);

        if (findProperty(doc, propertyName) != null) {
            throw new IllegalArgumentException("Property already exists: " + propertyName);
        }

        addNewProperty(doc, propertyName, value);
        saveDocument(doc, configPath);
    }

    /**
     * Restores the original config file from backup.
     *
     * @param configFileName The name of the config file
     * @throws IOException if file operations fail
     */
    public void restoreOriginalFile(String configFileName) throws IOException {
        Path configPath = getConfigPath(configFileName);
        Path backupPath = getBackupPath(configPath);

        if (Files.exists(backupPath)) {
            Files.copy(backupPath, configPath, StandardCopyOption.REPLACE_EXISTING);
            Files.delete(backupPath);
        }
    }

    private Path getConfigPath(String configFileName) {
        String configDir = composeFileName.contains("multihost") ? SSM_METASTORE_CONFIG_DIR : HMS_CONFIG_DIR ;
        Path path = Paths.get(configDir, configFileName);
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Config file not found: " + path);
        }
        return path;
    }

    private Path getBackupPath(Path configPath) {
        return configPath.getParent().resolve(configPath.getFileName() + BACKUP_SUFFIX);
    }

    private void createBackupIfNeeded(Path configPath) throws IOException {
        Path backupPath = getBackupPath(configPath);
        if (!Files.exists(backupPath)) {
            Files.copy(configPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private Document loadDocument(String configFileName) throws Exception {
        Path configPath = getConfigPath(configFileName);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(configPath.toFile());
    }

    private Element findProperty(Document doc, String propertyName) {
        NodeList properties = doc.getElementsByTagName("property");

        for (int i = 0; i < properties.getLength(); i++) {
            Element property = (Element) properties.item(i);
            String name = getPropertyName(property);

            if (propertyName.equals(name)) {
                return property;
            }
        }

        return null;
    }

    private String getPropertyName(Element property) {
        NodeList nameNodes = property.getElementsByTagName("name");
        return nameNodes.getLength() > 0 ? nameNodes.item(0).getTextContent().trim() : null;
    }

    private String getPropertyValue(Element property) {
        NodeList valueNodes = property.getElementsByTagName("value");
        return valueNodes.getLength() > 0 ? valueNodes.item(0).getTextContent() : null;
    }

    private void updatePropertyValue(Element property, String newValue) {
        NodeList valueNodes = property.getElementsByTagName("value");
        if (valueNodes.getLength() > 0) {
            valueNodes.item(0).setTextContent(newValue);
        } else {
            Element valueElement = property.getOwnerDocument().createElement("value");
            valueElement.setTextContent(newValue);
            property.appendChild(valueElement);
        }
    }

    private void addNewProperty(Document doc, String propertyName, String value) {
        Element root = doc.getDocumentElement();

        Element property = doc.createElement("property");

        Element name = doc.createElement("name");
        name.setTextContent(propertyName);
        property.appendChild(name);

        Element valueElement = doc.createElement("value");
        valueElement.setTextContent(value);
        property.appendChild(valueElement);

        root.appendChild(property);
    }

    private void saveDocument(Document doc, Path configPath) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(configPath.toFile());
        transformer.transform(source, result);
    }
}