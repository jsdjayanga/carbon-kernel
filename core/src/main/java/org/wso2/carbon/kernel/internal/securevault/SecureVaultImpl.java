package org.wso2.carbon.kernel.internal.securevault;

import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecureVault;

/**
 * Created by jayanga on 7/18/16.
 */
public class SecureVaultImpl implements SecureVault {
    private SecretRepository secretRepository;

    public SecureVaultImpl(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    @Override
    public char[] resolve(String alias) {
        return secretRepository.getSecret(alias);
    }
}
