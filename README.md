# STEGINSIGHT FORENSICS 🛡️
### Professional Neural Steganalysis & Digital Forensic Engine

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![React](https://img.shields.io/badge/Frontend-React%2018-cyan.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue.svg)](https://www.typescriptlang.org/)
[![AI-Powered](https://img.shields.io/badge/AI-Gemini%20Pro-orange.svg)](https://aistudio.google.com/)

**StegInsight Forensics** is a cutting-edge digital forensics engine designed for the high-fidelity detection and analysis of hidden data payloads within digital carriers. By fusing classical statistical methodologies—such as Chi-Square probability distribution and Shannon Entropy mapping—with modern neural heuristics, the platform systematically identifies steganographic anomalies in images, audio, and video files that often bypass standard security protocols. Developed for professional investigators and cybersecurity researchers, StegInsight transforms complex byte-level data into clear forensic verdicts and actionable intelligence, providing a robust defense against sophisticated covert communication channels.

---

## 🚀 Getting Started: Using the Live Version

The easiest way to use **StegInsight Forensics** is through our live web application. No coding or installation is required!

**Live App URL:** [https://ais-pre-rpvochh3ls43tfhuul5oj4-397660586580.asia-southeast1.run.app](https://ais-pre-rpvochh3ls43tfhuul5oj4-397660586580.asia-southeast1.run.app)
*(Note: As the project evolves, you can also access it at [Red-Snow GitHub Pages](https://Red-Snow.github.io/StegInsight-Forensics))*

### Step-by-Step Guide for New Users:

1. **Obtain an API Key (Free):**
   * StegInsight uses Google's powerful AI to analyze technical data. You will need a free API key to unlock the "AI Analysis" panel.
   * Go to [Google AI Studio](https://aistudio.google.com/app/apikey) and sign in with your Google account.
   * Click **"Create API Key"** and copy the generated text string.
2. **Set Your Key in the App:**
   * Open the Live App URL.
   * In the top-right corner, click the **"SET-AUTH"** button.
   * Paste your Gemini API key into the secure vault and click **"AUTHORIZE SESSION"**. *(Your key is stored safely and only in your local browser).*
3. **Upload Evidence:**
   * Simply drag and drop any Image, Video, or Audio file into the main dashboard area, or click "CHOOSE LOCAL FILE" to browse your computer.
4. **Review Results:**
   * **Wait for the Engine:** The app will calculate Entropy, Chi-Squared distributions, and structural anomalies.
   * **AI Analysis:** Read the detailed breakdown the AI generates based on your specific file's statistics.
   * **Visualizing:** For images, switch to the "Bit-Plane Visualizer" tab to visually look for hidden manipulation!
5. **Extract Data:**
   * If the tool flags anomalies (like appended/padded payloads), click the **"EXTRACT"** button at the bottom right to open a Hex/ASCII interactive viewer and optionally download the hidden `.bin` file!

---

## 💻 Developer Installation Guide (For Newbies)

Want to run the code on your own computer, modify the interface, or study how it works? Follow this detailed step-by-step guide.

### Prerequisites (What you need installed first)
Before you start, make sure your computer has the following tools installed:
1. **Node.js (v18 or higher):** This is the engine that runs our code. Download it from [nodejs.org](https://nodejs.org/) and install it.
2. **Git:** This allows you to download the code repository. Download it from [git-scm.com](https://git-scm.com/).
3. **A Code Editor:** We highly recommend [Visual Studio Code (VS Code)](https://code.visualstudio.com/).

*To verify your tools are installed, open your Terminal (Mac/Linux) or Command Prompt/PowerShell (Windows) and type `node -v` and `git --version`. You should see version numbers pop up!*

### Step-by-Step Setup

**Step 1: Clone the Repository**
Open your terminal, navigate to where you want the folder to live (e.g., your Desktop), and run:
```bash
git clone https://github.com/Red-Snow/StegInsight-Forensics.git
```
*(This downloads the entire project to a folder called `StegInsight-Forensics`)*

**Step 2: Enter the Folder**
```bash
cd StegInsight-Forensics
```

**Step 3: Install Dependencies**
The project relies on some external code libraries (like React and Recharts). To download them locally, run:
```bash
npm install
```
*(This might take a minute or two. You will see a new folder pop up called `node_modules`)*

**Step 4: Configure AI Authentication (Optional but Recommended)**
To use the AI Analysis features locally, you can hardcode an environment key:
1. In the root of your folder, you will see a file named `.env.example`.
2. Rename `.env.example` to `.env`.
3. Open `.env` in VS Code and paste your Gemini API key:
   ```env
   GEMINI_API_KEY=your_actual_api_key_here
   ```

**Step 5: Start the Local Development Server**
Finally, spin up the application:
```bash
npm run dev
```

**Step 6: Open the App!**
Once the terminal says "ready", open your web browser and go to the link provided in the terminal (usually `http://localhost:5173` or `http://localhost:3000`).

Happy Hunting! 🕵️‍♂️

### 🧠 Neural Intelligence Layer (Gemini-Powered)
Unlike static scanners, StegInsight utilizes the **Gemini 1.5 Pro** engine to provide a semantic threat verdict. 
*   **Contextual Rationale:** Deep-segment analysis of byte-level anomalies.
*   **Automated Toolchain Logic:** Suggests exact commands for secondary extraction (e.g., `stegseek`, `binwalk`).
*   **Heuristic Risk Scoring:** Real-time probability mapping of infiltration status.

### 📊 Deep-Packet Analytics
*   **Shannon Entropy Mapping:** Visualizes localized information density to pinpoint encrypted volumes (e.g., VeraCrypt heads).
*   **Chi-Square Probability Distribution:** Detects non-random bit manipulation in LSB planes.
*   **Magic-Byte Anchor Scanning:** Identifies structural mismatches and trailer/header appending attacks (JPEG EOF anomalies).

### 👁️ Visual Evidence Suite
*   **Spatial Heatmaps:** Maps bit-level noise distribution.
*   **Bit-Plane Slicing (0-7):** Isolates individual LSB layers to reveal hidden spatial patterns.
*   **Audio/Video Heuristics:** Targets specialized containers like DeepSound or MP4 atom appending.

---

## 📑 Methodology & Logic

| Methodology | Purpose | Technical Indicator |
| :--- | :--- | :--- |
| **Entropy Vectoring** | Payload Density | H > 7.9 (Compressed/Encrypted) |
| **LSB Slicing** | Masking Detection | Snowy spatial noise in Plane 0 |
| **Chi-Square Test** | Bit Frequency | p-value skew in natural distribution |
| **Neural Vault** | Semantic Verdict | AI-driven threat classification |

---

## 👤 Project Author

**Farman Khan (Red-Snow)**
*Digital Forensic Specialist & Full-Stack Architect*

> "Building digital shields for an era of hidden threats."

[![GitHub](https://img.shields.io/badge/GitHub-Red--Snow-lightgrey?logo=github)](https://github.com/Red-Snow)
[![Email](https://img.shields.io/badge/Email-FarmanKhan001%40gmail.com-red?logo=gmail)](mailto:FarmanKhan001@gmail.com)

---

## ⚖️ License
Licensed under **Apache 2.0**. See the [LICENSE](./LICENSE) file for more details.
