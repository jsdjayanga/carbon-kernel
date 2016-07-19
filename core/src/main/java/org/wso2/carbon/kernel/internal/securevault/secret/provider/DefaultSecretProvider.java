package org.wso2.carbon.kernel.internal.securevault.secret.provider;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;
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
 * Created by jayanga on 7/13/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.secret.provider.DefaultSecretProvider",
        immediate = true,
        property = {
                "capabilityName=SecretProvider",
                "secretProviderName=default"
        }
)
public class DefaultSecretProvider implements SecretProvider {
    private static Logger logger = LoggerFactory.getLogger(DefaultSecretProvider.class);
    private boolean isPermanentFile = false;

    @Activate
    public void activate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Activating {}", this.getClass().getName());
        }
    }

    @Deactivate
    public void deactivate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Deactivating {}", this.getClass().getName());
        }
    }

    @Override
    public void provide(List<Secret> secrets) throws SecureVaultException {
        Path passwordFilePath = Paths.get(Utils.getCarbonHome().toString(), "password");
        if (Files.exists(passwordFilePath)) {
            readSecretsFile(passwordFilePath, secrets);
        } else {
            readSecretsFromConsole(secrets);
        }
    }

    private void readSecretsFile(Path passwordFilePath, List<Secret> secrets) throws SecureVaultException {
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

            for (Secret secret : secrets) {
                secret.setSecretValue(properties.getProperty(secret.getSecretName(), ""));
            }

            inputStream.close();

            if (!isPermanentFile) {
                if (!passwordFilePath.toFile().delete()) {
                    passwordFilePath.toFile().deleteOnExit();
                }
            }
        } catch (IOException e) {
            throw new SecureVaultException("Failed to load secret file " + passwordFilePath.toFile());
        }
    }

    private void readSecretsFromConsole(List<Secret> secrets) throws SecureVaultException {
        Console console = System.console();
        if (console != null) {
            for (Secret secret : secrets) {
                secret.setSecretValue(new String(console.readPassword("[%s]",
                        "Enter " + secret.getSecretName() + " Password :")));
            }
        }
    }
}
