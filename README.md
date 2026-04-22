# STEGINSIGHT FORENSICS 🛡️
### Professional Neural Steganalysis & Digital Forensic Engine

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![React](https://img.shields.io/badge/Frontend-React%2018-cyan.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue.svg)](https://www.typescriptlang.org/)
[![AI-Powered](https://img.shields.io/badge/AI-Gemini%20Pro-orange.svg)](https://aistudio.google.com/)

**StegInsight Forensics** is an advanced digital forensics engine built to detect hidden data payloads (steganography) inside images, audio, and video files. 

By combining classical statistical methods (Chi-Square, Shannon Entropy) with modern neural intelligence, StegInsight translates complex byte-level anomalies into clear, actionable intelligence. It's designed to help investigators, cybersecurity researchers, and students uncover covert communication channels effortlessly.

---

## 🚀 Getting Started: Live Web App

The easiest way to use **StegInsight Forensics** is through our live web application. No coding or installation is required!

**Live App URL:** 👉 **[https://red-snow.github.io/StegInsight-Forensics/](https://red-snow.github.io/StegInsight-Forensics/)**

### Step-by-Step Guide:

1. **Obtain a Free API Key:**
   * StegInsight uses Google's AI model to generate technical analysis reports. You need a free API key to unlock the "AI Analysis" panel.
   * Go to [Google AI Studio](https://aistudio.google.com/app/apikey) and sign in.
   * Click **"Create API Key"** and copy the generated text string.
2. **Set Your Key in the App:**
   * Open the Live App URL.
   * In the top-right corner, click **"SET-AUTH"**.
   * Paste your Gemini API key and click **"AUTHORIZE SESSION"**. *(Your key is stored securely and locally in your browser).*
3. **Upload Evidence:**
   * Drag and drop any Image, Video, or Audio file into the dashboard, or click "CHOOSE LOCAL FILE" to browse your computer.
4. **⏳ Wait for Deep Packet Analysis:**
   * **IMPORTANT:** Please wait for the initial **Deep Packet Analysis** to fully complete after uploading your file. 
   * Features like the *AI Technical Analysis*, *Recommended Actions*, *Extract Payload*, and *PDF Report* rely on data from this scan and **will not work** until it finishes.
5. **Review & Extract:**
   * **AI Analysis:** Read the AI's detailed structural breakdown of your file.
   * **Visualizers:** Switch to the "Bit-Plane Visualizer" or "Heatmap" tabs to spot visual anomalies.
   * **Extract Data:** Click the **"EXTRACT"** button to open the Raw Payload Extracted modal, where you can view the Hex/ASCII dump and download the hidden `.bin` file.

---

## 💻 Local Developer Installation

Want to run the code locally, modify the interface, or study how it works? 

### Prerequisites
* **Node.js (v18+)**: [Download Here](https://nodejs.org/)
* **Git**: [Download Here](https://git-scm.com/)

### Step-by-Step Setup

**1. Clone the Repository:**
```bash
git clone https://github.com/Red-Snow/StegInsight-Forensics.git
cd StegInsight-Forensics
```

**2. Install Dependencies:**
```bash
npm install
```

**3. Configure AI Authentication (Optional):**
To use AI feature locally without manual web input:
* Rename `.env.example` to `.env`
* Add your key: `VITE_GEMINI_API_KEY=your_actual_api_key_here`

**4. Start the Application:**
```bash
npm run dev
```
Open your browser to `http://localhost:5173` (or the URL provided in your terminal).

---

## ⚙️ Core Features & Capabilities

### 🧠 Neural Intelligence Layer
* **Contextual Rationale:** Deep-segment AI analysis of byte-level anomalies.
* **Automated Toolchain Logic:** Suggests exact CLI commands for secondary extraction (e.g., `stegseek`, `binwalk`, `zsteg`).

### 📊 Deep-Packet Analytics
* **Shannon Entropy Mapping:** Visualizes localized data density to pinpoint encrypted payloads.
* **Chi-Square Test:** Detects non-random bit manipulation in LSB (Least Significant Bit) planes.
* **Magic-Byte Profiling:** Identifies structural mismatches and trailer/header appending attacks (e.g., JPEG EOF anomalies).

### 👁️ Visual Evidence Suite
* **Spatial Heatmaps:** Maps bit-level noise distribution.
* **Bit-Plane Slicing (0-7):** Isolates individual LSB layers to reveal hidden structural patterns.
* **Extraction Modal:** Hex/ASCII previewer and `.bin` raw payload downloading.

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
