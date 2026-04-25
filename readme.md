# 🛡️ KudoScan: Autonomous Phishing Triage Copilot ( For UM Hackathon Purposes )

**KudoScan** is an end-to-end platform built for modern threat detection. It combines an autonomous Telegram Bot that hunts for phishing links with a real-time, glassmorphism-styled React dashboard to triage and visualize threats.

## **KudoScan Video Pitching** 
Google Drive : https://drive.google.com/drive/folders/1eG9XFzKhOtiA_3xvfg1pc9gFZcl3ao3k?usp=drive_link

## 📥 What to Download (Prerequisites)

Before you can run this project, you must download and install the following software on your computer:

1. **[Python (3.8 or higher)](https://www.python.org/downloads/)**: Required to run the backend API and the Telegram bot. _(Make sure to check the box that says "Add Python to PATH" during installation)._
2. **[Node.js (v16 or higher)](https://nodejs.org/)**: Required to run the React frontend dashboard.
3. **[Git](https://git-scm.com/downloads)**: Required to clone this repository to your machine.
4. **[Visual Studio Code (VS Code)](https://code.visualstudio.com/)**: Recommended code editor for running the multiple terminals required.

### 🔑 Required API Keys

You will also need to generate the following free API keys to make the bot engine function:

- **Telegram Bot Token**: Create a new bot via [@BotFather](https://core.telegram.org/bots#6-botfather) on Telegram and copy the HTTP API token.
- **VirusTotal API Key**: Sign up at [VirusTotal](https://www.virustotal.com/) for a free API key to scan URLs.
- **Z.AI API Key**: Required for the autonomous threat analysis engine.

---

## ⚙️ Step-by-Step Setup Guide

To run the full KudoScan suite locally, you will need **three separate terminal windows** running simultaneously in VS Code.

### Step 1: Download the Code & Insert API Keys

First, download the code to your local machine and set up your credentials.

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)

# Navigate into the project folder
cd YOUR_REPO_NAME

```

### Step 2: Start the Backend API (Terminal 1)

This Python backend acts as the bridge, reading threat data from the SQLite database and serving it to the dashboard.

```bash
# 1. Ensure you are in the root project folder
# 2. Create a Python virtual environment
python -m venv venv

# 3. Activate the virtual environment
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 4. Install the required Python libraries
pip install fastapi uvicorn pyTelegramBotAPI

# 5. Start the backend server
uvicorn main:app --reload
```

### Step 3: Start the Frontend Dashboard (Terminal 2)

```bash
# 1. Open a NEW terminal window in VS Code
# 2. Navigate into the frontend folder
cd kudo-frontend

# 3. Install the required Node dependencies (Tailwind, React, Lucide Icons)
npm install tailwindcss@3.4.1 postcss autoprefixer axios lucide-react

# 4. Start the dashboard server
npm start
```

### Step 4: Start the Telegram Bot (Terminal 3)

This runs the autonomous bot that listens to your Telegram chat, scans links, and writes threats to the database.

```bash
# 1. Open a THIRD terminal window in VS Code
# 2. Ensure you are in the root project folder (not kudo-frontend)
# 3. Activate the virtual environment again
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 4. Run the bot script
# Install if there is error
pip install python-dotenv pyTelegramBotAPI requests anthropic streamlit
python bot.py
```

## 🧪 How to Use the System (Live Demo)

1. Once all three terminals are running without errors, you can test the full pipeline:

2. Open the KudoScan Dashboard in your browser (http://localhost:3000).

3. Open your connected Telegram Bot on your phone or desktop app.

4. Send a suspicious or malicious link to the bot (for example: http://promo-codes.online or http://bantuan-malaysia19.agronet-my.com).

5. Watch the bot analyze, grade, and flag the threat in the Telegram chat using its AI triage engine.

6. Go back to the Dashboard, click the "Refresh Data" button in the top right corner.

7. Watch the Live Scan Database instantly update with the new threat, and observe the High/Medium/Low Risk gauges recalculate in real-time!

* Built for Windows
