package org.wso2.carbon.axis2.osgi;

import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class Axis2RuntimeOSGiTest {
    @Test
    public void testCarbonAxis2Runtime() {
        Assert.assertNotNull(new Object(), "Sample Test");
    }
}
