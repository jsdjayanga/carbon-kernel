package org.wso2.carbon.kernel.securevault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.SecureVault;
import org.wso2.carbon.kernel.securevault.SecureVaultException;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Map;

/**
 * Created by jayanga on 7/7/16.
 */
public class SecureVaultConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(SecureVault.class);
    private Map<String, Object> secretRepositoryConfig;

    public SecureVaultConfiguration(Path configFilePath) throws SecureVaultException {
        try (InputStream inputStream = new FileInputStream(configFilePath.toFile())) {

            // TODO : pass the inputStream to deployment properties to get the updated values before creating the Yaml

            Yaml yaml = new Yaml();
            Map<String, Object> configuration = (Map<String, Object>) yaml.load(inputStream);
            if (configuration == null || configuration.isEmpty()) {
                throw new SecureVaultException("Failed to load secure vault configuration yaml : " + configFilePath);
            }
            logger.debug("Secure vault configurations parsed successfully.");

            secretRepositoryConfig = (Map<String, Object>) configuration.get("secretRepository");
            if (secretRepositoryConfig == null || secretRepositoryConfig.isEmpty()) {
                throw new SecureVaultException("Secret repository configurations not found : " + configFilePath);
            }
            logger.debug("Secret repository configurations loaded successfully.");
        } catch (IOException e) {
            throw new SecureVaultException("Failed to read secure vault configuration file : " + configFilePath, e);
        }
    }

    public String getString(String key) {
        Object object = secretRepositoryConfig.get(key);
        if (object instanceof String) {
            return (String) object;
        }
        return null;
//        throw new SecureVaultException("Configuration value is not of type String, key : " + key);
    }

    public String getString(String... keys) {
        Map<String, Object> config = secretRepositoryConfig;
        Object object;
        for (int i = 0; i < keys.length; i++) {
            object = config.get(keys[i]);
            if (object instanceof Map) {
                config = (Map<String, Object>) object;
                continue;
            }

            if (object instanceof String && i == keys.length - 1) {
                return (String) object;
            }
        }
        return null;
//        throw new SecureVaultException("Configuration value is not of type String, keys : " + Arrays.toString(keys));
    }

    public boolean exist(String key) {
        Object object = secretRepositoryConfig.get(key);
        if (object != null) {
            return true;
        }
        return false;
    }
}
