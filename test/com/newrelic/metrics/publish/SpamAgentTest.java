package com.newrelic.metrics.publish;

import com.newrelic.metrics.publish.configuration.ConfigurationException;
import org.junit.Test;

public class SpamAgentTest {

    @Test
    public void testAgentCreation() throws ConfigurationException {
        SpamAgent sa = new SpamAgent("host1", "/var/log/nginx", "%Y/%m/%d %H:%M", "", "", "", "");
    }

    @Test
    public void testPollCycle() throws ConfigurationException {
        SpamAgent sa = new SpamAgent("host1", "/var/log/nginx", "%Y/%m/%d %H:%M", "", "", "", "");
        sa.pollCycle();
    }
}
