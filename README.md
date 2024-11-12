# 
webscan - Multi-Tool Web Vulnerability Scanner

webscan is a tool that automates the scanning of web applications for vulnerabilities using multiple security tools. This guide will walk you through the steps to set up the necessary environment and install webscan on your system.

---

Prerequisites

- Operating System: webscan works best on Kali Linux. It’s also compatible with Parrot and Ubuntu systems.
- Python: You’ll need Python 3 (version 3.6 or later).

Step 1: Install Git

Git is used to clone the webscan repository. Run the following command to install it:
sudo apt update
sudo apt install git

Step 2: Install Python Virtual Environment

Setting up a Python virtual environment keeps dependencies organized and prevents conflicts. You may need to install the python3-venv package to create virtual environments:
sudo apt install python3-venv

---

Installation

Step 1: Clone the webscan Repository

Clone the webscan repository to your system using Git:
git clone https://github.com/arunpadigem21/webscan.git

Step 2: Navigate to the webscan Directory

Move into the newly created webscan directory:
cd webscan

Step 3: Set Up a Virtual Environment

To avoid conflicts, it’s best to install webscan and its dependencies in a virtual environment:

1. Create a virtual environment (named myenv here):
   python3 -m venv myenv

2. Activate the virtual environment:
   source myenv/bin/activate

When the environment is active, your command line prompt should change, showing (myenv) at the beginning.

Step 4: Install webscan

Inside the activated virtual environment, install webscan by running:
python3 -m pip install .

---

Running webscan

To run webscan, make sure you are in the correct directory (webscan) and that the virtual environment is activated.

Usage Example

Run webscan by specifying the target URL (replace example.com with the target you want to scan):
python3 webscan.py example.com

---

Troubleshooting

- Error: No such file or directory: webscan.py
  - Ensure you’re in the correct directory (cd webscan).
  - Verify that webscan.py exists with ls.

- Error: python3-venv is not available
  - Make sure your package list is updated: sudo apt update.
  - Then try installing again: sudo apt install python3-venv.

---

Exiting the Virtual Environment

To exit the virtual environment after running webscan:
deactivate

---

Uninstalling

To remove webscan, simply delete the webscan directory:
rm -rf webscan

---

Additional Notes

- Docker: webscan also has Docker support (under development).
- Updating: To update webscan, pull the latest changes from the repository:
  git pull origin master

For more details on usage and features, visit the webscan GitHub Repository: https://github.com/arunpadigem21/webscan.

This should help beginners with each step of setting up and running webscan. Let me know if you need any further details!
