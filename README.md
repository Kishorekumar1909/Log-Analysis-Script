# Log Analysis

![Python](https://img.shields.io/badge/Language-Python-brightgreen.svg)

## Table of Content
  * [Overview](#Problem-statment)
  * [How to run](#How-to-run)
  * [Screenshots](#screenshots)

  
## Overview

This Python script analyzes web server log files to extract useful information about requests, endpoint usage, and potential security concerns. It implements three main functionalities and saves the analysis results into a CSV file.

1. Functionalities
The script performs the following tasks:

  1.1 Count Requests per IP Address:

    * Extracts all IP addresses from the log file.
    * Counts how many requests were made by each IP.
    * Displays the results in descending order.

  1.2 Identify the Most Frequently Accessed Endpoint:

    * Extracts resource paths (e.g., /home, /login) from the log file.
    * Determines the most accessed endpoint and its access count.

  1.3 Detect Suspicious Activity (Brute Force Detection):

    * Identifies failed login attempts based on specific patterns (e.g., HTTP 401 or "Invalid credentials").
    * Flags IP addresses exceeding a threshold of failed login attempts (default: 10). I used thershold as 5 in screenshots output.
    * Displays flagged IP addresses and their failed login counts.

  1.4 Save Results to CSV:

    Organizes the results into a structured format and saves them to a file named log_analysis_results.csv with three sections:

    * Requests per IP
    * Most Accessed Endpoint
    * Suspicious Activity

2. Key Benefits

    * Provides insights into server activity and resource usage.
    * Helps identify potential security risks, such as brute force attempts.
    * Generates a CSV report for further analysis or record-keeping.


## How to run
  
**Step-1:** Download the files in the repository.<br>

**Step-2:** Get into the downloaded folder, open command prompt in 'script.py' directory. Run the command<br>
```python
python script.py
```


**Step-3:** Enter the file name and make sure file is in 'script.py' file location.

![C__Windows_System32_cmd exe - python  script py 12_8_2024 12_18_17 AM](https://github.com/user-attachments/assets/af55cadf-dbdf-4e3c-82df-cefcdbb5752c)



**Step-4:** Run the command to view the results in CSV file<br> 
```python
log_analysis_results.csv
```
![script py - Log Analysis - Visual Studio Code 12_8_2024 5_53_59 PM](https://github.com/user-attachments/assets/75dfb0b6-8855-4f2e-aeda-d936f6604345)



## Screenshots


![C__Windows_System32_cmd exe - python  script py 12_8_2024 12_18_17 AM](https://github.com/user-attachments/assets/af55cadf-dbdf-4e3c-82df-cefcdbb5752c)

![Screenshot 12_8_2024 12_16_32 AM](https://github.com/user-attachments/assets/6a4cedf9-60d4-4189-b9a8-e57b3ddc5f99)

![script py - Log Analysis - Visual Studio Code 12_8_2024 5_53_59 PM](https://github.com/user-attachments/assets/75dfb0b6-8855-4f2e-aeda-d936f6604345)

![log_analysis_results - Excel (Unlicensed Product) 12_8_2024 5_59_58 PM](https://github.com/user-attachments/assets/8b7de6ca-6577-4113-820e-5ab5d9d79381)

![log_analysis_results csv - Log Analysis - Visual Studio Code 12_8_2024 12_17_18 AM](https://github.com/user-attachments/assets/34558517-520a-4328-beae-3db64b1c0ef1)


  
