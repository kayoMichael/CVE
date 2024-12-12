# CVE Utility

This is a simple utility to fetch CVE details from the [National Vulnerability Database](https://nvd.nist.gov/). and [CVE Mitre](https://cve.mitre.org/). \
It is written in Python, JavaScript, HTML and Tailwind CSS. \
The AI model used for AI suggestion is [llama-3.1-70b](https://ai.meta.com/blog/meta-llama-3-1/)

## Setup

### Windows OS

1. Download the Repository as a Zip File (For non-git user).
2. Extract the Zip File.
3. Open the extracted folder in Command Prompt.
4. Run the following setup Command
   ```shell
   cmd /c execute.bat all
   ```
5. Create A .txt file with a list of CVEs in the same directory
6. Run the following Command to run the script. It will ask for a cve file so give the cve.txt file as input
    ```shell
    cmd /c execute.bat run
    ```
7. To end the server, run control + C in the command prompt.


### Linux/Mac OS
1. Download the Repository as a Zip File (For non-git user).
2. Extract the Zip File.
3. Open the extracted folder in Command Prompt.
4. Run the following setup Command
   ```shell
   make all
   ```
5. Create A .txt file with a list of CVEs in the same directory
6. Run the following Command to run the script. It will ask for a cve file so give the cve.txt file as input
    ```shell
    make run
    ```
7. To end the server, run cmd + C in the command prompt.
