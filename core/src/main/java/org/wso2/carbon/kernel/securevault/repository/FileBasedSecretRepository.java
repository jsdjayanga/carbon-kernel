package org.wso2.carbon.kernel.securevault.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.SecureVaultException;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.keystore.KeyStoreProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by jayanga on 7/7/16.
 */
public class FileBasedSecretRepository implements SecretRepository {
    private static final Logger logger = LoggerFactory.getLogger(FileBasedSecretRepository.class);
    private final Map<String, String> secrets = new HashMap<String, String>();
    private KeyStore keyStore;
    private Cipher cipher;

    @Override
    public void init(SecureVaultConfiguration secretRepositoryConfig) throws SecureVaultException {
        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(secretRepositoryConfig);
        keyStore = keyStoreProvider.getKeyStore();

        String location = secretRepositoryConfig.getString("location");
        SecretsFilesHandler secretsFilesHandler = new SecretsFilesHandler(location);
        Properties properties = secretsFilesHandler.getAllSecrets();
        decryptSecrests(properties);
    }

    @Override
    public String getSecret(String alias) {
        if (alias != null && !alias.isEmpty()) {
            String secret = secrets.get(alias);
            if (secret != null) {
                return secret;
            }
        }
        return alias;
    }

    private static class SecretsFilesHandler {
        private static final Logger logger = LoggerFactory.getLogger(SecretsFilesHandler.class);

        Path mainSecretsFilePath;
        Path fragmentFilePath;

        SecretsFilesHandler(String location) throws SecureVaultException {
            if (location.endsWith("secrets.properties")) {
                mainSecretsFilePath = Paths.get(location);
                Path temp = mainSecretsFilePath.getParent();
                if (temp != null) {
                    fragmentFilePath = Paths.get(temp.toString(), "secrets.d");
                } else {
                    throw new SecureVaultException("Unable to deduce the fragment file location");
                }
            } else {
                mainSecretsFilePath = Paths.get(location, "secrets.properties");
                fragmentFilePath = Paths.get(location, "secrets.d");
            }
        }

        Properties getAllSecrets() throws SecureVaultException {
            Properties properties = new Properties();
            loadSecretFile(mainSecretsFilePath, properties);
            loadSecretFragmentFiles(fragmentFilePath, properties);
            return properties;
        }

        void loadSecretFragmentFiles(Path filePath, Properties properties) throws SecureVaultException {
            if (Files.exists(filePath) && Files.isDirectory(filePath)) {
                File[] files = filePath.toFile().listFiles();
                if (files != null) {
                    for (int i = 0; i < files.length; i++) {
                        loadSecretFile(files[i].toPath(), properties);
                    }
                }
            }
        }

        void loadSecretFile(Path filePath, Properties properties) throws SecureVaultException {
            try (InputStream inputStream = new FileInputStream(filePath.toFile())) {
                properties.load(inputStream);
            } catch (FileNotFoundException e) {
                throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                        + filePath + ")", e);
            } catch (IOException e) {
                throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                        + filePath + ")", e);
            }
        }
    }

    private void decryptSecrests(Properties properties) throws SecureVaultException {
        for (Object alias : properties.keySet()) {
            String key = String.valueOf(alias);
            String encryptedText = properties.getProperty(key);
            String decryptedText = "";

            String[] tokens = encryptedText.split(" ");
            if ("cipherText".equals(tokens[0])) {

                // TODO : read these info from from properties
                try {
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
                    try {
                        // TODO : read these info from from properties
                        cipher = Cipher.getInstance("RSA");
                        try {
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);
                            decryptedText = new String(decrypt(tokens[1].trim()
                                    .getBytes(Charset.forName("UTF-8"))), Charset.forName("UTF-8"));
                        } catch (InvalidKeyException e) {
                            // TODO: remove this line
                            logger.error("   ", e);
                        }
                    } catch (NoSuchPaddingException e) {
                        // TODO: remove this line
                        logger.error("   ", e);
                    }
                } catch (KeyStoreException e) {
                    // TODO: remove this line
                    logger.error("   ", e);
                } catch (NoSuchAlgorithmException e) {
                    // TODO: remove this line
                    logger.error("   ", e);
                } catch (UnrecoverableKeyException e) {
                    // TODO: remove this line
                    logger.error("   ", e);
                }
            } else if ("plainText".equals(tokens[0])) {
                decryptedText = tokens[1];
            } else {
                // TODO: log error
            }

            //String decryptedText = new String(baseCipher.decrypt(encryptedText.trim().getBytes()));
            secrets.put(key, decryptedText);
        }
    }




    // TODO :==================================
    // REMOVE THIS

    public byte[] decrypt(byte[] inputStream) throws SecureVaultException {
        InputStream sourceStream = new ByteArrayInputStream(inputStream);
        try {
            sourceStream = decode(sourceStream);
        } catch (IOException e) {
            throw new SecureVaultException("IOError when decoding the input " +
                    "stream for cipher ", e);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream out = new CipherOutputStream(baos, cipher);

        byte[] buffer = new byte[64];
        int length;
        try {
            while ((length = sourceStream.read(buffer)) != -1) {
                out.write(buffer, 0, length);
            }
        } catch (IOException e) {
            throw new SecureVaultException("IOError when reading the input" +
                    " stream for cipher ", e);
        } finally {
            try {
                sourceStream.close();
                out.flush();
                out.close();
            } catch (IOException ignored) {
                // ignore exception
            }
        }

        return baos.toByteArray();
    }

    public static InputStream decode(InputStream inputStream)
            throws IOException, SecureVaultException {

        byte[] decodedValue = Base64.getDecoder().decode(asBytes(inputStream));
        //byte[] decodedValue = Base64.getDecoder().decode(IOUtils.readFully());

        return new ByteArrayInputStream(decodedValue);
    }

    private static byte[] asBytes(InputStream in) throws SecureVaultException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        try {
            while ((len = in.read(buffer)) >= 0) {
                out.write(buffer, 0, len);
            }
        } catch (IOException e) {
            throw new SecureVaultException("Error during converting a inputstream " +
                    "into a byte array ", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                }
            }
            try {
                out.close();
            } catch (IOException ignored) {
            }
        }
        return out.toByteArray();
    }

    // TODO: ==================================
}
