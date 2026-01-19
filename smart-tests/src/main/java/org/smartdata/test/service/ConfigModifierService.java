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

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

@Service
public class ConfigModifierService {

//    private final String CONFIG_DIR = "target/test-classes/env/multihost/ssm-conf";
    private final String CONFIG_DIR = "target/test-classes/env/demo-cluster/ssm-conf";
    private final Map<String, Map<String, String>> originalValues = new HashMap<>();

    /**
     * Sets a property value in the specified XML configuration file.
     * Backs up the original value for restoration.
     *
     * @param configFileName The name of the config file (e.g., "smart-site-master.xml")
     * @param propertyName The property name (e.g., "smart.cmdlet.executors")
     * @param newValue The new value to set
     * @throws Exception if file operations fail
     */
    public void setProperty(String configFileName, String propertyName, String newValue) throws Exception {
        Path configPath = Paths.get(CONFIG_DIR, configFileName);
        if (!Files.exists(configPath)) {
            throw new IllegalArgumentException("Config file not found: " + configPath);
        }

        // Backup original file if not already backed up
        Path backupPath = configPath.getParent().resolve(configFileName + ".backup");
        if (!Files.exists(backupPath)) {
            Files.copy(configPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
        }

        // Parse XML
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(configPath.toFile());

        // Find and update property
        NodeList properties = doc.getElementsByTagName("property");
        boolean found = false;

        for (int i = 0; i < properties.getLength(); i++) {
            Element property = (Element) properties.item(i);
            NodeList names = property.getElementsByTagName("name");
            if (names.getLength() > 0) {
                String name = names.item(0).getTextContent().trim();
                if (propertyName.equals(name)) {
                    NodeList values = property.getElementsByTagName("value");
                    if (values.getLength() > 0) {
                        Node valueNode = values.item(0);
                        String originalValue = valueNode.getTextContent();

                        // Store original value
                        originalValues.computeIfAbsent(configFileName, k -> new HashMap<>())
                            .put(propertyName, originalValue);

                        // Update value
                        valueNode.setTextContent(newValue);
                        found = true;
                        break;
                    }
                }
            }
        }

        if (!found) {
            throw new IllegalArgumentException("Property not found: " + propertyName);
        }

        // Write back to file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(configPath.toFile());
        transformer.transform(source, result);
    }

    /**
     * Restores the original value of a property.
     *
     * @param configFileName The name of the config file
     * @param propertyName The property name
     * @throws Exception if file operations fail
     */
    public void restoreProperty(String configFileName, String propertyName) throws Exception {
        String originalValue = originalValues.getOrDefault(configFileName, new HashMap<>()).get(propertyName);
        if (originalValue != null) {
            setProperty(configFileName, propertyName, originalValue);
            originalValues.get(configFileName).remove(propertyName);
        }
    }

    /**
     * Restores all modified properties in a config file.
     *
     * @param configFileName The name of the config file
     * @throws Exception if file operations fail
     */
    public void restoreAllProperties(String configFileName) throws Exception {
        Map<String, String> fileOriginals = originalValues.get(configFileName);
        if (fileOriginals != null) {
            for (Map.Entry<String, String> entry : fileOriginals.entrySet()) {
                setProperty(configFileName, entry.getKey(), entry.getValue());
            }
            originalValues.remove(configFileName);
        }
    }

    /**
     * Restores the original config file from backup.
     *
     * @param configFileName The name of the config file
     * @throws Exception if file operations fail
     */
    public void restoreOriginalFile(String configFileName) throws Exception {
        Path configPath = Paths.get(CONFIG_DIR, configFileName);
        Path backupPath = configPath.getParent().resolve(configFileName + ".backup");

        if (Files.exists(backupPath)) {
            Files.copy(backupPath, configPath, StandardCopyOption.REPLACE_EXISTING);
            Files.delete(backupPath);
            originalValues.remove(configFileName);
        }
    }

    /**
     * Gets the current value of a property.
     *
     * @param configFileName The name of the config file
     * @param propertyName The property name
     * @return The current value, or null if not found
     * @throws Exception if file operations fail
     */
    public String getProperty(String configFileName, String propertyName) throws Exception {
        Path configPath = Paths.get(CONFIG_DIR, configFileName);
        if (!Files.exists(configPath)) {
            return null;
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(configPath.toFile());

        NodeList properties = doc.getElementsByTagName("property");
        for (int i = 0; i < properties.getLength(); i++) {
            Element property = (Element) properties.item(i);
            NodeList names = property.getElementsByTagName("name");
            if (names.getLength() > 0) {
                String name = names.item(0).getTextContent().trim();
                if (propertyName.equals(name)) {
                    NodeList values = property.getElementsByTagName("value");
                    if (values.getLength() > 0) {
                        return values.item(0).getTextContent();
                    }
                }
            }
        }
        return null;
    }
}
