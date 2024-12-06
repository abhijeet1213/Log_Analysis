## Log_Analysis

🚀 Project Overview

The Log Analysis Script is a Python-based tool designed to analyze web server logs for critical insights. 
It parses logs, performs analysis, and detects suspicious activities such as brute-force login attempts. 
The project is especially useful for cybersecurity and server administrators to monitor and secure their systems.


📋 Features

1. Count Requests per IP Address:
   - Extracts all IP addresses from the log file.
   - Counts the number of requests for each IP.
   - Outputs results in descending order.

2. Identify the Most Frequently Accessed Endpoint:
   - Determines the most accessed resource/URL.
   - Displays the endpoint and the access count.

3. Detect Suspicious Activity:
   - Identifies brute-force login attempts by flagging IPs with excessive failed login attempts (default threshold: 10).
   - Displays flagged IP addresses with their failed login attempt counts.

4. Save Results to CSV:
   - Outputs results in a clear format to the terminal.
   - Saves the analysis in "log_analysis_results.csv".


🛠️ Technologies Used

- Libraries:
  - csv
  - collections
  - re
  - argparse (for optional command-line arguments)


📁 Project Structure

log_analysis/                     
|___ sample.log                  --> Sample log file...
|___ log_analysis.py             --> Main Python script...
|___ log_analysis_results.csv    --> created CSV file...
|___ requirements.txt            --> Dependencies (if any)...
|___ README.md                   --> Project documentation...
