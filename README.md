# CVE Utility

An AI-powered Full Stack Application designed to retrieve and analyze Common Vulnerabilities and Exposures (CVE) data based on user input, leveraging public sources such as the [National Vulnerability Database](https://nvd.nist.gov/) and [CVE Mitre](https://cve.mitre.org/) for accurate and comprehensive information.

## Features

- Bulk CVE information retrieval.
- Basic Filtering and Searching Capabilities.
- Vulnerability analysis
- AI-powered Solutions using Meta's [llama-3.1-70b](https://ai.meta.com/blog/meta-llama-3-1/) model

## Demo

https://github.com/user-attachments/assets/e16df379-db0a-4bc1-8dd7-b5364cfa2238

## Installation

Please Refer to the [Installation Demo](https://github.com/kayoMichael/CVE/edit/main/README.md#installation-demo) for an Example
### Windows

1. **Get the Code**
   - Option 1: Download ZIP
     - Click "Code" → "Download ZIP" on the repository page
     - Extract the ZIP file to your desired location
     - Open the extracted folder in Command Prompt
   - Option 2: Clone with Git (For Git users Only)
     ```shell
     git clone https://github.com/kayoMichael/CVE.git
     cd CVE
     ```

2. **Run Setup**
   ```shell
   cmd /c execute.bat all
   ```

### Linux/macOS

1. **Get the Code**
   - Option 1: Download ZIP
     - Click "Code" → "Download ZIP" on the repository page
     - Extract the ZIP file to your desired location
     - Open the Extracted folder in Terminal
   - Option 2: Clone with Git (For Git users Only)
     ```shell
     git clone https://github.com/kayoMichael/CVE.git
     cd CVE
     ```

2. **Run Setup**
   ```shell
   make all
   ```

## Usage

### Preparing Input

1. Create a text file containing your CVE list
   - One CVE ID per line
   - Example format:
     ```
     CVE-2024-1234
     CVE-2024-5678
     ```
   - Save the file in the project directory

### Running the Utility

#### Windows
```shell
cmd /c execute.bat run
```

#### Linux/macOS
```shell
make run
```

Follow the prompts inside command prompt/terminal to:
1. Enter your input file name or the directory path to your file name.
2. Wait for processing (it may take serveral minutes for CVE Lists of 600+)
3. View results in your web browser

### Stopping the Server
- Windows: Press `Ctrl + C` in Command Prompt
- Linux/macOS: Press `Cmd + C` in Terminal

## Troubleshooting

### Unknown CVE Inputs

The Utility will automatically skip CVEs that are not found in the database. Please Check the Terminal/Command Prompt for any errors.

#### Sample Not Found Error Message
```commandline
The CVE code CVE-2023-29832 is not found in the database. Skipping...
```

### Connection Issues

1. **Connection Problems (OPS Employees)**
   - For People using the utility in the Office: Make sure Global Protect Region is set to Canada Central
   - Try the following command in the Terminal/Command Prompt. If it fails, it is a OPS network Issue.
     ```shell
     pip install numpy
     ```

2. **API Availability**
   - CVE Mitre API may have scheduled maintenance
   - Check terminal/Command Prompt for specific error messages
   - Retry after a few minutes if servers are down

#### Sample Connection Error Message (Also Triggers if All CVE input is Unknown)
```commandline
Server is most likely down or Service is temporarily suspended. Please Check a sample site like https://www.cve.org/CVERecord?id=CVE-2022-22971
If the Server is running, In addition, Make sure Global Protect is in Central Canada for best result
Please also make sure the CVE codes are valid in the text file inputted.
```

## Installation Demo
https://github.com/user-attachments/assets/9c87b0a7-d43d-4563-8731-2f37a7176b3c




