package org.wso2.carbon.kernel.internal.securevault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Created by jayanga on 7/12/16.
 */
public class SecureVaultConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultConfiguration.class);
    private static final SecureVaultConfiguration INSTANCE = new SecureVaultConfiguration();
    private boolean initialized = false;
    private Map<String, Object> secretRepositoryConfig;

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
            secretRepositoryConfig = (Map<String, Object>) yaml.load(inputStream);
            if (secretRepositoryConfig == null || secretRepositoryConfig.isEmpty()) {
                throw new SecureVaultException("Failed to load secure vault configuration yaml : "
                        + configFileLocation);
            }
            logger.debug("Secure vault configurations parsed successfully.");

            secretRepositoryConfig = (Map<String, Object>) secretRepositoryConfig.get("secretRepository");
            if (secretRepositoryConfig == null || secretRepositoryConfig.isEmpty()) {
                throw new SecureVaultException("Secret repository configurations not found : " + configFileLocation);
            }
            initialized = true;
            logger.debug("Secret repository configurations loaded successfully.");
        } catch (IOException e) {
            throw new SecureVaultException("Failed to read secure vault configuration file : " + configFileLocation, e);
        }
    }

    public String getString(String key) {
        Object object = secretRepositoryConfig.get(key);
        if (object instanceof String) {
            return (String) object;
        }
        return null;
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
    }

    public List<String> getList(String... keys) {
        Map<String, Object> config = secretRepositoryConfig;
        Object object;
        for (int i = 0; i < keys.length; i++) {
            object = config.get(keys[i]);
            if (object instanceof Map) {
                config = (Map<String, Object>) object;
                continue;
            }

            if (object instanceof List && i == keys.length - 1) {
                return (List<String>) object;
            }
        }
        return null;
    }

    public boolean exist(String key) {
        Object object = secretRepositoryConfig.get(key);
        if (object != null) {
            return true;
        }
        return false;
    }
}
