# NetGuard AI — Live Console Screenshots Directory
This directory holds real-world screenshots captured from your deployed web application at **https://netguardai.duckdns.org/**.

When you drop PNG or JPG screenshot files into this folder, **`generate_user_manual_pdf.py`** automatically detects them, scales them to high-resolution vector dimensions, and embeds them directly under their corresponding sidebar feature section in **`NetGuard_AI_Sidebar_Feature_User_Manual.pdf`**!

---

### 📸 Recommended Screenshot Naming Convention:

| Target Sidebar Feature | Recommended Filename |
|---|---|
| **1. 🏠 Overview** | `01_overview.png` |
| **2. 🌐 Live Traffic** | `02_live_traffic.png` |
| **3. 📊 Traffic Analytics** | `03_traffic_analytics.png` |
| **4. 🚨 Threat Detection** | `04_threat_detection.png` |
| **5. 🌍 Global Threat Map** | `05_global_threat_map.png` |
| **6. 🧬 Zero-Day Deep Engine** | `06_zero_day_engine.png` |
| **7. ⚔️ Red vs Blue War-Room** | `07_war_room.png` |
| **8. 🛡️ MITRE ATT&CK Matrix** | `08_mitre_matrix.png` |
| **9. ⚡ Agentic SOC Copilot** | `09_agentic_copilot.png` |
| **10. 🕸️ Network Topology** | `10_network_topology.png` |
| **11. 🤖 ML Insights** | `11_ml_insights.png` |
| **12. 🎯 Adversarial Red-Team** | `12_adversarial_tester.png` |
| **13. 🧠 SOC AI Assistant** | `13_soc_assistant.png` |
| **14. 📁 Dataset Analysis** | `14_dataset_analysis.png` |
| **15. 📈 Data Visualization Explorer** | `15_data_visualization.png` |
| **16. 📜 Prediction History** | `16_prediction_history.png` |
| **17. 📋 User Alert History** | `17_alert_history.png` |
| **18. 🕓 Incident Timeline** | `18_incident_timeline.png` |
| **19. ⚙️ System Status** | `19_system_status.png` |
| **20. 🛠️ Settings & About** | `20_settings_about.png` |

---

### 🚀 How to Capture and Embed:
1. Open your browser and go to your live app: **https://netguardai.duckdns.org/**.
2. Click on any sidebar page (for example, **🌍 Global Threat Map** or **⚔️ Red vs Blue War-Room**).
3. Press **Win + Shift + S** (Windows Snipping Tool) or **PrtScn** to take a screenshot.
4. Save the image into this folder (`docs/screenshots/05_global_threat_map.png`).
5. Run the PDF generator in PowerShell:
   ```powershell
   .\.venv\Scripts\python.exe generate_user_manual_pdf.py
   ```
6. Open **`NetGuard_AI_Sidebar_Feature_User_Manual.pdf`** to see your live screenshot embedded with an official figure caption!
