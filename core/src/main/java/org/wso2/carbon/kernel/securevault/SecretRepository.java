package org.wso2.carbon.kernel.securevault;

import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * Created by jayanga on 7/12/16.
 */
public interface SecretRepository {
    void init(SecureVaultConfiguration secretRepositoryConfig, List<Secret> secrets) throws SecureVaultException;
    char[] getSecret(String alias);
}
