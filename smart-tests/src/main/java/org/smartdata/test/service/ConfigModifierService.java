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

import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
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

  private static final String PROPERTY_TAG = "property";
  private static final String NAME_TAG = "name";
  private static final String VALUE_TAG = "value";
  private static final String BACKUP_SUFFIX = ".backup";
  private static final String CONFIG_DIR = "ssm-conf";
  private static final int INDENT_AMOUNT = 4;

  /**
   * Gets the current value of a property.
   *
   * @param configFileName The name of the config file
   * @param propertyName The property name
   * @return The current value, or null if not found
   * @throws IOException if file operations fail
   */
  public String getProperty(String configFileName, String propertyName) throws IOException {
    try {
      Document doc = loadDocument(configFileName);
      Element property = findProperty(doc, propertyName);
      return property != null ? getPropertyValue(property) : null;
    } catch (Exception e) {
      throw new IOException("Failed to read property from config file: " + configFileName, e);
    }
  }

  /**
   * Sets a property value in the specified XML configuration file.
   * Creates a backup if it doesn't exist. Updates existing property or creates new one.
   *
   * @param configFileName The name of the config file (e.g., "smart-site-master.xml")
   * @param propertyName The property name (e.g., "smart.cmdlet.executors")
   * @param newValue The new value to set
   * @throws IOException if file operations fail
   */
  public void setProperty(String configFileName, String propertyName, String newValue) throws IOException {
    modifyProperty(configFileName, propertyName, newValue, true);
  }

  /**
   * Adds a new property to the configuration file.
   * Throws an exception if the property already exists.
   *
   * @param configFileName The name of the config file
   * @param propertyName The property name
   * @param value The property value
   * @throws IOException if file operations fail
   */
  public void addProperty(String configFileName, String propertyName, String value) throws IOException {
    modifyProperty(configFileName, propertyName, value, false);
  }

  /**
   * Restores the original config file from backup.
   *
   * @param configFileName The name of the config file
   * @throws IllegalArgumentException if config file is not found
   * @throws IOException if file operations fail
   */
  public void restoreOriginalFile(String configFileName) throws IOException {
    Path configPath = validateAndGetConfigPath(configFileName);
    Path backupPath = getBackupPath(configPath);
    if (Files.exists(backupPath)) {
      Files.copy(backupPath, configPath, StandardCopyOption.REPLACE_EXISTING);
      Files.delete(backupPath);
    }
  }

  /**
   * Core method for modifying properties in configuration files.
   * Handles both adding new properties and updating existing ones.
   *
   * @param configFileName The name of the config file
   * @param propertyName The property name
   * @param value The property value
   * @param allowUpdate If true, updates existing properties; if false, throws exception if property exists
   * @throws IOException if file operations fail
   */
  private void modifyProperty(String configFileName, String propertyName, String value, boolean allowUpdate)
      throws IOException {
    try {
      Path configPath = validateAndGetConfigPath(configFileName);
      createBackupIfNeeded(configPath);
      Document doc = loadDocument(configFileName);
      Element property = findProperty(doc, propertyName);
      if (property != null) {
        if (!allowUpdate) {
          throw new IllegalArgumentException("Property already exists: " + propertyName);
        }
        updatePropertyValue(property, value);
      } else {
        addNewProperty(doc, propertyName, value);
      }
      saveDocument(doc, configPath);
    } catch (Exception e) {
      throw new IOException("Failed to modify property in config file: " + configFileName, e);
    }
  }

  private Path getConfigDirectory() {
    return Paths.get(composeFileName).getParent().resolve(CONFIG_DIR);
  }

  private Path validateAndGetConfigPath(@NonNull String configFileName) {
    Path path = getConfigDirectory().resolve(configFileName);
    if (Files.notExists(path)) {
      throw new IllegalArgumentException("Config file not found: " + path);
    }
    return path;
  }

  private Path getBackupPath(Path configPath) {
    return configPath.getParent().resolve(configPath.getFileName() + BACKUP_SUFFIX);
  }

  private void createBackupIfNeeded(Path configPath) throws IOException {
    Path backupPath = getBackupPath(configPath);
    if (Files.notExists(backupPath)) {
      Files.copy(configPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private Document loadDocument(String configFileName) throws Exception {
    Path configPath = validateAndGetConfigPath(configFileName);
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(configPath.toFile());
  }

  private Element findProperty(Document doc, String propertyName) {
    NodeList properties = doc.getElementsByTagName(PROPERTY_TAG);
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
    NodeList nameNodes = property.getElementsByTagName(NAME_TAG);
    return nameNodes.getLength() > 0 ? nameNodes.item(0).getTextContent().trim() : null;
  }

  private String getPropertyValue(Element property) {
    NodeList valueNodes = property.getElementsByTagName(VALUE_TAG);
    return valueNodes.getLength() > 0 ? valueNodes.item(0).getTextContent() : null;
  }

  private void updatePropertyValue(Element property, String newValue) {
    NodeList valueNodes = property.getElementsByTagName(VALUE_TAG);
    if (valueNodes.getLength() > 0) {
      valueNodes.item(0).setTextContent(newValue);
    } else {
      Element valueElement = property.getOwnerDocument().createElement(VALUE_TAG);
      valueElement.setTextContent(newValue);
      property.appendChild(valueElement);
    }
  }

  private void addNewProperty(Document doc, String propertyName, String value) {
    Element root = doc.getDocumentElement();
    root.appendChild(doc.createTextNode(StringUtils.repeat(" ", INDENT_AMOUNT)));
    Element property = doc.createElement(PROPERTY_TAG);
    Element name = doc.createElement(NAME_TAG);
    name.setTextContent(propertyName);
    property.appendChild(name);
    Element valueElement = doc.createElement(VALUE_TAG);
    valueElement.setTextContent(value);
    property.appendChild(valueElement);
    root.appendChild(property);
  }

  private void saveDocument(Document doc, Path configPath) throws Exception {
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer transformer = transformerFactory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", String.valueOf(INDENT_AMOUNT));
    DOMSource source = new DOMSource(doc);
    StreamResult result = new StreamResult(configPath.toFile());
    transformer.transform(source, result);
  }
}