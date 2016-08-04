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

package org.wso2.carbon.kernel.securevault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;

/**
 * Secure Vault Configuration.
 *
 * @since 5.2.0
 */
public class SecureVaultConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultConfiguration.class);
    private static final SecureVaultConfiguration INSTANCE = new SecureVaultConfiguration();
    private boolean initialized = false;
    private Map<String, Object> secureVaultConfiguration;

    private SecureVaultConfiguration() {
    }

    public static SecureVaultConfiguration getInstance() throws SecureVaultException {
        if (INSTANCE.initialized) {
            return INSTANCE;
        }

        synchronized (INSTANCE) {
            if (!INSTANCE.initialized) {
                INSTANCE.init();
            }
        }
        return INSTANCE;
    }

    private void init() throws SecureVaultException {
        String configFileLocation = Utils.getSecureVaultYAMLLocation();
        try (InputStream inputStream = new FileInputStream(configFileLocation)) {

            // TODO : pass the inputStream to deployment properties to get the updated values before creating the Yaml
            // ConfigUtil.parse(inputStream);

            Yaml yaml = new Yaml();

            secureVaultConfiguration = Optional.ofNullable((Map<String, Object>) yaml.load(inputStream))
                    .filter(stringObjectMap -> !stringObjectMap.isEmpty())
                    .orElseThrow(() -> new SecureVaultException(
                            "Failed to load secure vault configuration yaml : " + configFileLocation));

            logger.debug("Secure vault configurations parsed successfully.");

            initialized = true;
            logger.debug("Secret repository configurations loaded successfully.");
        } catch (IOException e) {
            throw new SecureVaultException("Failed to read secure vault configuration file : " + configFileLocation, e);
        }
    }

    public Optional<String> getString(String... keys) {
        Map<String, Object> config = secureVaultConfiguration;
        Object object;
        for (int i = 0; i < keys.length; i++) {
            object = config.get(keys[i]);
            if (object instanceof Map) {
                config = (Map<String, Object>) object;
                continue;
            }

            if (object instanceof String && i == keys.length - 1) {
                return Optional.ofNullable((String) object);
            }
        }
        return Optional.empty();
    }
}
