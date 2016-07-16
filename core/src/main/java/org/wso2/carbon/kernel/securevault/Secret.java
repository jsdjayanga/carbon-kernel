package org.wso2.carbon.kernel.securevault;

/**
 * Created by jayanga on 7/13/16.
 */
public class Secret {
    private String secretName;
    private String secretValue;

    public Secret(String secretName) {
        this.secretName = secretName;
    }

    public String getSecretName() {
        return secretName;
    }

    public String getSecretValue() {
        return secretValue;
    }

    public void setSecretValue(String secretValue) {
        this.secretValue = secretValue;
    }
}
