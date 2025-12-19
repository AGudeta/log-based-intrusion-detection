import java.io.BufferedReader;
import java.io.IOException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.Iterator;

/**
 * Blue Team Log Detector (JAVA)
 * 
 * Reads a simplified authiniticaiton log file, detects suspicious activity, and writes the results to an incident style output file.
 * 
 * Exptected input line format (one event per line): yyyy-MM-dd HH:mm:ss FAIL|SUCCESS user=... ip=...
 * 
 * Detection Rules:
 * 1. Brute force by IP: >= IP_FAIL_THRESHOLD FAILED_LOGIN within WINDOW_MINUTES.
 * 2. Targeted account: >= USER_FAIL_THRESHOLD total FAILED_LOGIN for a user.
 * 3. Possible Comporime: SUCCESS_LOGIN from an IP that has been flagged for brute force.
 */

public final class LogDetector {
    // Detection rules
    private static final int IP_FAIL_THRESHOLD = 5; //>= 5 fails
    private static final int WINDOW_MINUTES = 10; //... within 10 minutes
    private static final int USER_FAIL_THRESHOLD = 8; //>= 8 total fails for user

    //Timestamp format used in the log lines
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private LogDetector() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents one parsed log event(one line).
     */
    private static final class Event {
        final LocalDateTime time;
        final String type; // FAIL or SUCCESS login
        final String user;
        final String ip;

        Event(LocalDateTime time, String type, String user, String ip) {
            this.time = time;
            this.type = type;
            this.user = user;
            this.ip = ip;
        }
    }

    /**
     * Parses a single log line into an Event object.
     * @return 
     * - Event if parsing succeeds 
     * - null if the line is not a valid log line.
     */
    private static Event parseLine(String line) {
        //Split on whitespace
        String[] parts = line.trim().split("\\s+");
        //Need at least: data, time, type, user=, ip=
        if (parts.length < 5) {
            return null;
        }

        //parts[0] = yyyy-MM-dd
        //parts[1] = HH:mm:ss
        LocalDateTime time = LocalDateTime.parse(parts[0] + " " + parts[1], TS);

        //parts[2] = FAIL or SUCCESS
        String type = parts[2];

        //find user= and ip=
        String user = null;
        String ip = null;
        for (int i = 3; i < parts.length; i++) {
            if (parts[i].startsWith("user=")) {
                user = parts[i].substring("user=".length());
            } else if (parts[i].startsWith("ip=")) {
                ip = parts[i].substring("ip=".length());
            }
        }

        if (user == null || ip == null) {
            return null;
        }

        return new Event(time, type, user, ip);
    }

    /**
     * Removes timestamps from 'times' that are older than WINDOW_MINUTES from relative to 'newest'.
     * 
     */
    private static void pruneOldTimes(List<LocalDateTime> times, LocalDateTime newest) {
        Iterator<LocalDateTime> it = times.iterator();
        while(it.hasNext()) {
            LocalDateTime t =it.next();

            //Compute age in minutes: newest - t
            Duration duration = Duration.between(t, newest);
            long minutesOld = duration.toMinutes();
            if (minutesOld > WINDOW_MINUTES) {
                it.remove();
            }
        }
    }

    /**
     * Main detection logic
     */

    public static void main(String[] args) {
        String inputPath = (args.length >= 1) ? args[0] : "lib/auth.log";
        String outputPath = (args.length >= 2) ? args[1] : "bin/report.txt";

        //Data structures for detection
        
        //For each IP, store timestamps of FAILED_LOGIN within the rolling window
        Map<String, List<LocalDateTime>> failedTimesByIp = new HashMap<>();

        //Tootal FAILED_LOGIN per user
        Map<String, Integer> failedCountByUser = new HashMap<>();

        //Flagged IPs and usernames
        Set<String> flaggedIps = new HashSet<>();
        Set<String> flaggedUsers = new HashSet<>();

        //If a flagged IP later has SUCCESS_LOGIN, add here
        List<String> possibleCompormises = new ArrayList<>();

        //Report friendly details for IP window (largest window we observed)
        Map<String, Integer> maxWindowFailsByIp = new HashMap<>();
        Map<String, LocalDateTime> windowStartByIp = new HashMap<>();
        Map<String, LocalDateTime> windowEndByIp = new HashMap<>();

        //Track how many lines were skipped (not valid log lines)
        int malformedLines = 0;

        //Read and process each line of the log file
        try (BufferedReader br = new BufferedReader(new FileReader(inputPath))) {
            String line; 
            while ((line = br.readLine()) != null) {
                //Conver one raw line into a structured Event obect;
                Event e = parseLine(line);
                if (e == null) {
                    malformedLines++;
                    continue;
                }

                //Case: FAILED_LOGIN
                if ("FAILED_LOGIN".equals(e.type)) {
                    //Rule 1: Brute force by IP

                    //Make sure the IP key exists in the map
                    failedTimesByIp.putIfAbsent(e.ip, new ArrayList<>());

                    //Add this failure time
                    List<LocalDateTime> times = failedTimesByIp.get(e.ip);
                    times.add(e.time);

                    //remove timestamps outside the rolling WINDOW_MINUTES window
                    pruneOldTimes(times, e.time);
                    
                    //Count failures in the current rolling window
                    int windowCount = times.size();

                    //Save the best (largest) window counts for the report
                    int prevBest = maxWindowFailsByIp.getOrDefault(e.ip, 0);
                    if (windowCount > prevBest) {
                        maxWindowFailsByIp.put(e.ip, windowCount);
                        windowStartByIp.put(e.ip, times.get(0));
                        windowEndByIp.put(e.ip, times.get(times.size() - 1));
                    }

                    //If the rolling window count reaches threshold, flag the IP
                    if (windowCount >= IP_FAIL_THRESHOLD) {
                        flaggedIps.add(e.ip);
                    }

                    //Rule 2: Target account by username total
                    int newTotal = failedCountByUser.getOrDefault(e.user, 0) + 1;
                    failedCountByUser.put(e.user, newTotal);

                    if (newTotal >= USER_FAIL_THRESHOLD) {
                        flaggedUsers.add(e.user);
                    }
                } else if ("SUCCESS_LOGIN".equals(e.type)) {
                    //Rule 3: Success after a brute force pattern
                    //If an IP was already flagged and then succeeds, this can be high risk
                    if (flaggedIps.contains(e.ip)) {
                        possibleCompormises.add("Possible Compomise: time=" + e.time + " user=" + e.user + " (success after brute-force pattern)");
                    } 
                } else {
                    //unkown types ignored
                }
            }
                
        } catch (IOException e) {
                //If we can't read the input file, stop and print error
                System.out.println("Error reading input file: " + inputPath);
                System.out.println(e.getMessage());
                return;
            }
            /*
            Write Report
             */
        try (PrintWriter out = new PrintWriter(new FileWriter(outputPath))) {
                out.println("Report");
                out.println("Input: " + inputPath);
                out.println("Malformed lines skipped: " + malformedLines);
                out.println();

                //Flagged IPs
                out.println(" 1. Flagged IPs (Brute force):");
                out.println();
                if (flaggedIps.isEmpty()) {
                    out.println("None");
                } else {
                    for (String ip : flaggedIps) {
                        out.println("IP: "+ ip);
                        out.println("Max fails in " + WINDOW_MINUTES + " min window: " + maxWindowFailsByIp.getOrDefault(ip, 0));
                        LocalDateTime start = windowStartByIp.get(ip);
                        LocalDateTime end = windowEndByIp.get(ip);
                        if (start != null && end != null) {
                            out.println("Window: " + start + " to " + end); 
                        } 
                            out.println();

                    }
                }
                // Flagged usernames
                out.println("2. Flagged Usernames (Targeted accounts)");
                out.println();
                if (flaggedUsers.isEmpty()) {
                out.println("None");
                    } else {
                        for (String user : flaggedUsers) {
                            out.println("User: " + user + " | total failed logins: " + failedCountByUser.getOrDefault(user, 0));
                            
                        }

                }
                out.println();

                //Possible compormise signals
                out.println("3. Possible Compormises (Success after brute force pattern)");
                out.println();
                if (possibleCompormises.isEmpty()) {
                    out.println("None");

                } else {
                    for (String s : possibleCompormises) {
                        out.println(s);
                    }
                }

            } catch (IOException e) {
                System.out.println("Error writing output file: " + outputPath);
                System.out.println(e.getMessage());
                return;
            }
            System.out.println("Done. Report written to: " + outputPath);

    }
}
