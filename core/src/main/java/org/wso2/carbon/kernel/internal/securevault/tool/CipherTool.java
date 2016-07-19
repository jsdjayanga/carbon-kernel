package org.wso2.carbon.kernel.internal.securevault.tool;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.cipher.EncryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreProvider;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreType;
import org.wso2.carbon.kernel.internal.securevault.secret.provider.DefaultSecretProvider;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jayanga on 7/18/16.
 */
public class CipherTool {
    private static final Logger logger = Logger.getLogger(CipherTool.class.getName());
    private SecureVaultConfiguration secureVaultConfiguration;
    private List<Secret> secrets;

    public static void main(String[] args) {
        logger.info("####### WSO2 CipherTool #######");
        CipherTool cipherTool;
        try {
            cipherTool = new CipherTool();
            cipherTool.execute(args);
        } catch (SecureVaultException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }
    }

    public CipherTool() throws SecureVaultException {
        secureVaultConfiguration = SecureVaultConfiguration.getInstance();

        SecretProvider secretProvider = new DefaultSecretProvider();
        secrets = new ArrayList<>();
        secrets.add(new Secret("masterPassword"));
        secretProvider.provide(secrets);

        String keystoreType = secureVaultConfiguration.getString("keystore", "type");
        String keystoreLocation = secureVaultConfiguration.getString("keystore", "location");
        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(KeyStoreType.valueOf(keystoreType),
                keystoreLocation, SecureVaultUtils.getSecret(secrets, "masterPassword").getSecretValue());
        KeyStore keyStore = keyStoreProvider.getKeyStore();

        String algorithm = secureVaultConfiguration.getString("keystore", "algorithm");
        String privateKeyAlias = secureVaultConfiguration.getString("keystore", "alias");

        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = "RSA";
        }

        EncryptionHandler encryptionHandler = new EncryptionHandler(keyStore, privateKeyAlias, algorithm);

        String secretPropertiesFileLocation = secureVaultConfiguration.getString("location");
        if (secretPropertiesFileLocation == null || secretPropertiesFileLocation.isEmpty()) {
            secretPropertiesFileLocation = Utils.getSecretsPropertiesLocation();
        }
        Properties secretsProperties = SecureVaultUtils.loadSecretFile(Paths.get(secretPropertiesFileLocation));

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String encryptedText = secretsProperties.getProperty(key);

            String[] tokens = encryptedText.split(" ");
            if ("plainText".equals(tokens[0])) {
                byte[] encryptedPassword = encryptionHandler.encrypt(tokens[1].trim().toCharArray());
                secretsProperties.setProperty(key,
                        "cipherText " + new String(SecureVaultUtils.toChars(encryptedPassword)));
            }
        }

        SecureVaultUtils.updateSecretFile(Paths.get(secretPropertiesFileLocation), secretsProperties);
    }

    private void execute(String[] args) {
        logger.info("Executing...");

    }
}
