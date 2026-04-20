# STEGINSIGHT FORENSICS 🛡️
### Professional Neural Steganalysis & Digital Forensic Engine

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![React](https://img.shields.io/badge/Frontend-React%2018-cyan.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue.svg)](https://www.typescriptlang.org/)
[![AI-Powered](https://img.shields.io/badge/AI-Gemini%20Pro-orange.svg)](https://aistudio.google.com/)

**StegInsight** is a cutting-edge digital forensics platform designed for the high-fidelity detection and analysis of hidden data payloads. By fusing classical statistical probability with modern neural heuristics, StegInsight empowers investigators to uncover covert communication channels that bypass standard security audits.

---

## 🚀 Live Forensic Console
Access the production-grade analysis environment directly in your browser:
👉 **[LAUNCH STEGINSIGHT CONSOLE](https://Red-Snow.github.io/StegInsight-Forensics)**

---

## 💎 Core Forensic Pillars

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

## 🛠️ Developer Installation

1.  **Clone & Install:**
    ```bash
    git clone https://github.com/Red-Snow/StegInsight-Forensics.git
    cd StegInsight-Forensics
    npm install
    ```

2.  **AI Authentication:**
    Create a `.env` file in the root directory:
    ```env
    GEMINI_API_KEY=your_api_key_here
    ```

3.  **Deploy Local Console:**
    ```bash
    npm run dev
    ```

---

## ⚖️ License
Licensed under **Apache 2.0**. See the [LICENSE](./LICENSE) file for more details.
