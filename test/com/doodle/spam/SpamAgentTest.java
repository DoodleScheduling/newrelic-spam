package com.doodle.spam;

import com.newrelic.metrics.publish.configuration.ConfigurationException;
import org.junit.Test;

public class SpamAgentTest {

    @Test
    public void testAgentCreation() throws ConfigurationException {
        SpamAgent sa = new SpamAgent("host1", "/var/log/nginx/error.log", "yyyy/MM/dd HH:mm", "request: \"(GET|POST|PUT|DELETE)", "(GET|POST|PUT|DELETE) (/.*) HTTP", "client: ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}),", "client: (\\w*:\\w*:\\*:\\w*:\\w*:\\w*),");
    }

    @Test
    public void testPollCycle() throws ConfigurationException {
        SpamAgent sa = new SpamAgent("host1", "/var/log/nginx/error.log", "yyyy/MM/dd HH:mm", "request: \"(GET|POST|PUT|DELETE)", "(GET|POST|PUT|DELETE) (/.*) HTTP", "client: ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}),", "client: (\\w*:\\w*:\\w*:\\w*:\\w*:\\w*),");
        sa.pollCycle();
    }
}
