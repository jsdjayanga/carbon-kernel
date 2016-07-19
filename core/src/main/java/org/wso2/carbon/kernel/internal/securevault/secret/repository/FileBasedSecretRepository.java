package org.wso2.carbon.kernel.internal.securevault.secret.repository;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.cipher.DecryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreProvider;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreType;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Created by jayanga on 7/12/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.secret.repository.FileBasedSecretRepository",
        immediate = true,
        property = {
                "capabilityName=SecretRepository",
                "secretRepositoryType=file"
        }
)
public class FileBasedSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(FileBasedSecretRepository.class);
    private final Map<String, char[]> secrets = new HashMap<>();

    @Activate
    public void activate() {
        logger.info("===================FileBasedSecretRepository activate");
    }

    @Deactivate
    public void deactivate() {
        logger.info("===================FileBasedSecretRepository deactivate");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, List<Secret> secrets)
            throws SecureVaultException {
        logger.info("===================initializing FileBasedSecretRepository");

        String secretPropertiesFileLocation = secureVaultConfiguration.getString("location");
        if (secretPropertiesFileLocation == null || secretPropertiesFileLocation.isEmpty()) {
            secretPropertiesFileLocation = Utils.getSecretsPropertiesLocation();
        }
        Properties encryptedSecrets = loadSecretFile(Paths.get(secretPropertiesFileLocation));


        String keystoreType = secureVaultConfiguration.getString("keystore", "type");
        String keystoreLocation = secureVaultConfiguration.getString("keystore", "location");
        String privateKeyAlias = secureVaultConfiguration.getString("keystore", "alias");
        Secret masterPassword = SecureVaultUtils.getSecret(secrets, "masterPassword");
        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, "privateKeyPassword");

        String algorithm = secureVaultConfiguration.getString("keystore", "algorithm");
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = "RSA";
        }

        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(KeyStoreType.valueOf(keystoreType),
                keystoreLocation, masterPassword.getSecretValue());
        KeyStore keyStore = keyStoreProvider.getKeyStore();


        DecryptionHandler decryptionHandler = new DecryptionHandler(keyStore, privateKeyAlias,
                privateKeyPassword.getSecretValue().toCharArray(), algorithm);

        for (Object alias : encryptedSecrets.keySet()) {
            String key = String.valueOf(alias);
            String encryptedText = encryptedSecrets.getProperty(key);
            char[] decryptedPassword = new char[0];

            String[] tokens = encryptedText.split(" ");
            if ("cipherText".equals(tokens[0])) {
                decryptedPassword = SecureVaultUtils.toChars(decryptionHandler.decrypt(tokens[1].trim()));
            } else if ("plainText".equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                // TODO: log error
            }

            this.secrets.put(key, decryptedPassword);
        }
    }

    @Override
    public char[] getSecret(String alias) {
        char[] secret = secrets.get(alias);
        if (secret != null && secret.length != 0) {
            return secret;
        }
        return new char[0];
    }

    private Properties loadSecretFile(Path secretsFilePath) throws SecureVaultException {
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream(secretsFilePath.toFile())) {

            // TODO : Use ConfigUtil to update with environment variables

            properties.load(inputStream);
        } catch (FileNotFoundException e) {
            throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        } catch (IOException e) {
            throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        }
        return properties;
    }
}
