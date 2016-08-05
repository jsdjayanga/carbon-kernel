/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.kernel.securevault.reader;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.MasterKey;
import org.wso2.carbon.kernel.securevault.MasterKeyReader;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.wso2.carbon.kernel.utils.Utils;

import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;

/**
 * This service component is responsible for providing secrets to initialize the secret repositories. This provider
 * has two behaviours
 * 1. Reads the secrets from file
 * It looks for a property file with name "password" in server home directory, read the passwords and delete the
 * file. If the file has a property "permanent=true", the file will not be deleted.
 * 2. Reads the secrets from command line.
 * And this component registers a SecretProvider as an OSGi service.
 *
 * @since 5.2.0
 */
@Component(
        name = "org.wso2.carbon.kernel.securevault.reader.DefaultMasterKeyReader",
        immediate = true,
        property = {
                "capabilityName=org.wso2.carbon.kernel.securevault.SecretRetriever",
                "masterKeyReaderType=org.wso2.carbon.kernel.securevault.reader.DefaultMasterKeyReader"
        }
)
public class DefaultMasterKeyReader implements MasterKeyReader {
    private static Logger logger = LoggerFactory.getLogger(DefaultMasterKeyReader.class);
    private boolean isPermanentFile = false;

    @Activate
    public void activate() {
        logger.debug("Activating DefaultMasterKeyReader");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating DefaultMasterKeyReader");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration) throws SecureVaultException {
        // No initializations needed for the DefaultMasterKeyReader
    }

    @Override
    public void readMasterKeys(List<MasterKey> masterKeys) throws SecureVaultException {
        Path passwordFilePath = Paths.get(Utils.getCarbonHome().toString(), "password");
        if (Files.exists(passwordFilePath)) {
            readSecretsFile(passwordFilePath, masterKeys);
        } else {
            readSecretsFromConsole(masterKeys);
        }
    }

    private void readSecretsFile(Path passwordFilePath, List<MasterKey> masterKeys) throws SecureVaultException {
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream(passwordFilePath.toFile())) {
            properties.load(inputStream);
            if (properties.isEmpty()) {
                throw new SecureVaultException("Password file is empty " + passwordFilePath.toFile());
            }

            String permanentFile = properties.getProperty("permanent");
            if (permanentFile != null && !permanentFile.isEmpty()) {
                isPermanentFile = Boolean.parseBoolean(permanentFile);
            }

            for (MasterKey masterKey : masterKeys) {
                masterKey.setMasterKeyValue(properties.getProperty(masterKey.getMasterKeyName(), ""));
            }

            inputStream.close();

            if (!isPermanentFile && !passwordFilePath.toFile().delete()) {
                passwordFilePath.toFile().deleteOnExit();
            }
        } catch (IOException e) {
            throw new SecureVaultException("Failed to load secret file " + passwordFilePath.toFile(), e);
        }
    }

    private void readSecretsFromConsole(List<MasterKey> masterKeys) throws SecureVaultException {
        Console console = System.console();
        if (console != null) {
            for (MasterKey masterKey : masterKeys) {
                masterKey.setMasterKeyValue(new String(console.readPassword("[%s]",
                        "Enter master key '" + masterKey.getMasterKeyName() + "' :")));
            }
        }
    }
}
