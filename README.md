# CVE Utility

A utility for retrieving and analyzing Common Vulnerabilities and Exposures (CVE) information from authoritative sources including the [National Vulnerability Database](https://nvd.nist.gov/) and [CVE Mitre](https://cve.mitre.org/).

## Features

- Bulk CVE information retrieval
- Vulnerability analysis
- AI-powered suggestions using Meta's [llama-3.1-70b](https://ai.meta.com/blog/meta-llama-3-1/) model
- Basic Filtering and Searching Capabilities.

## Installation

### Windows

1. **Get the Code**
   - Option 1: Download ZIP
     - Click "Code" → "Download ZIP" on the repository page
     - Extract the ZIP file to your desired location
   - Option 2: Clone with Git
     ```shell
     git clone https://github.com/yourusername/cve-utility.git
     cd cve-utility
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
   - Option 2: Clone with Git
     ```shell
     git clone https://github.com/yourusername/cve-utility.git
     cd cve-utility
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
2. Wait for processing (it may take serveral minutes for CVE Lists of 200+)
3. View results in your web browser

### Stopping the Server
- Windows: Press `Ctrl + C` in Command Prompt
- Linux/macOS: Press `Cmd + C` in Terminal

## Troubleshooting

### Common Issues

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

## Demo
https://github.com/user-attachments/assets/9c87b0a7-d43d-4563-8731-2f37a7176b3c




