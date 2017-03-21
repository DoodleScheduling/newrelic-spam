package com.doodle.spam;

import com.newrelic.metrics.publish.Agent;
import com.newrelic.metrics.publish.configuration.ConfigurationException;
import com.newrelic.metrics.publish.util.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SpamAgent extends Agent {

    private static final Logger logger = Logger.getLogger(SpamAgent.class);

    private static final String GUID = "com.doodle.spamnginx";
    private static final String VERSION = "1.0.0";

    // Agent configuration, retrieved from plugin.json
    private final String name;

    // Regex patterns to match each part of the request
    private final Pattern patternMethod;
    private final Pattern patternIpv4;
    private final Pattern patternIpv6;
    private final Pattern patternEndpoint;
    private final String dateFormat;
    private final String logFile;

    public SpamAgent(String name, String logFile, String dateFormat, String patternMethod, String patternEndpoint, String patternIpv4, String patternIpv6) throws ConfigurationException {
        super(GUID, VERSION);
        this.name = name;
        this.patternMethod = Pattern.compile(patternMethod);
        this.patternEndpoint = Pattern.compile(patternEndpoint);
        this.patternIpv4 = Pattern.compile(patternIpv4);
        this.patternIpv6 = Pattern.compile(patternIpv6);
        this.dateFormat = dateFormat;
        this.logFile = logFile;
    }

    @Override
    public String getAgentName() {
        return name;
    }

    @Override
    public void pollCycle() {
        try {
            List<Spam> requests = getSpamLogs();

            logger.debug("Found " + requests.size() + " requests that were blocked.");

            Set<String> uniqueIpv4 = new HashSet<>();
            Set<String> uniqueIpv6 = new HashSet<>();
            Set<String> uniqueEndpoints = new HashSet<>();
            Integer blockedPost = 0;
            Integer blockedPut = 0;
            Integer blockedDelete = 0;

            for (Spam spam : requests) {
                if (spam.getIpv4client() != null) {
                    if (!uniqueIpv4.contains(spam.getIpv4client())) logger.debug("Added Ipv4: " + spam.getIpv4client());
                    uniqueIpv4.add(spam.getIpv4client());
                }

                if (spam.getIpv6client() != null) {
                    if (!uniqueIpv6.contains(spam.getIpv6client())) logger.debug("Added Ipv6: " + spam.getIpv6client());
                    uniqueIpv6.add(spam.getIpv6client());
                }

                if (!uniqueEndpoints.contains(spam.getEndpoint()))
                    logger.debug("Added endpoint: " + spam.getEndpoint());
                uniqueEndpoints.add(spam.getEndpoint());

                switch (spam.getMethod()) {
                    case "POST":
                        blockedPost++;
                        break;
                    case "DELETE":
                        blockedDelete++;
                        break;
                    case "PUT":
                        blockedPut++;
                }
            }
            logger.debug("Blocked requests: " + requests.size());
            logger.debug("Blocked unique Ipv4: " + uniqueIpv4.size());
            logger.debug("Blocked unique Ipv6: " + uniqueIpv6.size());
            logger.debug("Blocked POST: " + blockedPost);
            logger.debug("Blocked DELETE: " + blockedDelete);
            logger.debug("Blocked PUT: " + blockedPut);
            logger.debug("Blocked endpoints: " + uniqueEndpoints.size());

            reportMetric("Blocked requests", "requests", requests.size());
            reportMetric("Blocked clients Ipv4", "clients", uniqueIpv4.size());
            reportMetric("Blocked clients Ipv6", "clients", uniqueIpv6.size());
            reportMetric("Blocked method POST", "requests", blockedPost);
            reportMetric("Blocked method DELETE", "requests", blockedDelete);
            reportMetric("Blocked method PUT", "requests", blockedPut);
            reportMetric("Blocked endpoints", "endpoints", uniqueEndpoints.size());
        } catch (Exception e){
            // We don't want to report any metrics when there's an exception, otherwise we would be sending 0 when
            // in fact there could be data. It's preferable that we see a gap in the graphs.
            logger.error("There was an exception in this cycle. No data sent to new relic.");
        }
    }

    private List<Spam> getSpamLogs() throws RuntimeException, IOException, InterruptedException {
        List<Spam> logs = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(getCommand());
            Process process = pb.start();
            String line;

            // Read standard output
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = br.readLine()) != null) {
                logs.add(parseSpam(line));
            }

            // Read standard error
            br = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            StringBuilder output = new StringBuilder();
            while ((line = br.readLine()) != null) {
                output.append(line);
                output.append(System.getProperty("line.separator"));
            }

            // Wait for the command to finish
            int returnCode = process.waitFor();
            if (returnCode != 0 && returnCode != 1) {
                logger.error("Command '" + getReadableCommand() + "' returned code: " + returnCode);
                if (output.length() > 0) {
                    logger.error("Standard error: " + System.getProperty("line.separator") + output);
                }
                throw new RuntimeException();
            }
        } catch (Exception e) {
            logger.error(e, "Failed to execute " + getReadableCommand());
            throw e;
        }
        return logs;
    }

    private Spam parseSpam(String logentry) {
        logger.debug("Parsing: " + logentry);
        Matcher matcherMethod = patternMethod.matcher(logentry);
        Matcher matcherEndpoint = patternEndpoint.matcher(logentry);
        Matcher matcherIpv4 = patternIpv4.matcher(logentry);
        Matcher matcherIpv6 = patternIpv6.matcher(logentry);
        String method = matcherMethod.find() ? matcherMethod.group(1) : "UNKNOWN";
        String endpoint = matcherEndpoint.find() ? matcherEndpoint.group(2) : "Unknown";
        String ipv4 = matcherIpv4.find() ? matcherIpv4.group(1) : null;
        String ipv6 = matcherIpv6.find() ? matcherIpv6.group(1) : null;

        logger.debug("Parsed: method " + method + ", endpoint: " + endpoint + ", ipv4: " + ipv4 + ", ipv6: " + ipv6);
        return new Spam(method, endpoint, ipv4, ipv6);
    }

    private String[] getCommand() {
        return new String[]{"grep", new SimpleDateFormat(dateFormat).format(new Date()) + ".*limiting requests", logFile};
    }

    private String getReadableCommand() {
        String readableCommand = "";
        for (String i : getCommand()) {
            readableCommand += i + " ";
        }
        return readableCommand;
    }
}
