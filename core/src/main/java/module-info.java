module org.wso2.carbon.core {
    requires org.wso2.carbon.config;
    requires java.xml.bind;
    requires org.wso2.carbon.utils;
    requires slf4j.api;
    requires java.management;
    requires java.rmi;
    requires org.wso2.carbon.base;
    requires java.management.rmi;

    provides org.wso2.carbon.base.CarbonComponent
            with org.wso2.carbon.kernel.internal.runtime.RuntimeServiceListenerComponent,
                    org.wso2.carbon.kernel.internal.CarbonCoreComponent;

    uses org.wso2.carbon.kernel.runtime.Runtime;

    exports org.wso2.carbon.kernel.config.model;

    opens org.wso2.carbon.kernel.config.model;
}