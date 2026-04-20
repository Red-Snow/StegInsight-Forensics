# STEGINSIGHT FORENSICS 🛡️
### Advanced Neural Steganalysis & Digital Forensic Engine

**StegInsight** is a professional-grade digital forensics tool designed for deep-packet inspection of steganographic carriers. Built using TypeScript and React, it utilizes high-entropy vectoring, Chi-Square statistical probability, and neural-inspired heuristics to identify hidden payloads within images, audio, video, and documents.

---

## 🚀 Live Environment
**[ACCESS LIVE FORENSIC CONSOLE HERE](https://Red-Snow.github.io/steginsight-forensics)**

---

## 🛠️ Forensic Capabilities

### 1. Neural Heuristics Engine
Evaluates structural integrity across multiple MIME types to assign a **Likelihood of Infiltration** score.
- **Header/Footer Scan:** Detects magic-byte anomalies and trailer appending.
- **Shannon Entropy Vectoring:** Maps information density to identify encrypted containers.
- **DeepSound Signature Detection:** Specifically targets audio-infused payloads.

### 2. Advanced Visualizers
- **Spatial Heatmaps:** Visualizes noise distribution in pixel data.
- **LSB Bit-Plane Mapping:** Isolates the Least Significant Bit layers to find "snowy" patterns indicative of hidden data.
- **Sliding Window Entropy:** A time-domain graph showing exactly where data density spikes (the "Smoking Gun").

### 3. Professional reporting
- **Standardized Forensic PDF:** Generates multi-page reports including Chain of Custody, Technical Metrics, AI-Driven Rationales, and Recommended Actions.

---

## 🧩 Technical Deep Dive

### Detection Algorithms Used:
- **Chi-Square Test (First-Order Statistics):** Checks if pixel values follow a natural distribution or if they've been tampered with to store information.
- **Shannon Entropy (H):** Measures the randomness of bytes. Values near 8.0 in carrier trailers suggest encrypted volumes (e.g., OpenPuff, VeraCrypt).
- **Bit-Plane Slicing:** Extracts and greyscales individual bits from the color channels.

---

## 💻 Developer Setup

1. **Clone & Install:**
   ```bash
   git clone https://github.com/Red-Snow/steginsight-forensics.git
   cd steginsight-forensics
   npm install
   ```

2. **Environment Configuration:**
   Create a `.env` file and add your Gemini API key for the Forensic AI module:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```

3. **Run Console:**
   ```bash
   npm run dev
   ```

---

## ⚖️ License
Distributed under the Apache 2.0 License. See `LICENSE` for more information.
