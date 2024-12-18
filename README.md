# CVE Utility

A Utility to fetch CVE details from the [National Vulnerability Database](https://nvd.nist.gov/) and [CVE Mitre](https://cve.mitre.org/). \
It is written in Python, JavaScript, HTML and Tailwind CSS. \
The model used for AI suggestion is [llama-3.1-70b](https://ai.meta.com/blog/meta-llama-3-1/)

## Setup

### Windows OS
1. Download the Repository as a Zip File (Code -> Download ZIP)  or clone the repository (For Git users only).
2. Open the extracted folder in Command Prompt.
3. Run the following setup Command
   ```shell
   cmd /c execute.bat all
   ```


### Linux/Mac OS
1. Download the Repository as a Zip File (Code -> Download ZIP) or clone the repository (For Git users only).
2. Open the extracted folder in Terminal.
3. Run the following setup Command
   ```shell
   make all
   ```

## Running the Utility

### Windows OS
1. Create A .txt file with a list of CVEs in the same directory
2. Run the following Command to run the script.
    ```shell
    cmd /c execute.bat run
    ```
3. Input the cve file name into the command prompt when asked
4. To end the server, run control + C in the command prompt.

### Linux/Mac OS
1. Create A .txt file with a list of CVEs in the same directory
2. Run the following Command to run the script. It will ask for a cve file so give the cve.txt file as input
    ```shell
    make run
    ```
3. Input the cve file name into the Terminal when asked
4. To end the server, run cmd + C in the Terminal.

## TroubleShooting

### For OPS Employees in the Office
Please Set Global Protect Region to Canada Central If you are having issues connecting to the server.

### Temporary Problems
The Server that provides the API (Most likely CVE Mitre) is temporarily down sometimes due to maintenance. Please wait until the Server is back up and running to run the script again.
Check the Command Prompt/Terminal to see if there are error messages pertaining to the Server.
