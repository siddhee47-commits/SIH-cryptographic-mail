\# SecureMailScope — Member 1 Frontend



Frontend module for \*\*SIH26159 — SecureMailScope\*\*.



\## Member 1 Responsibility



\- React frontend

\- PCAP / PCAPNG upload interface

\- Security posture dashboard

\- Protocol and TLS summary

\- Security findings display

\- Backend API integration



\## Technology



\- React

\- Vite

\- JavaScript

\- CSS



\## Project Structure



```text

member1\_frontend/

│

├── index.html

├── package.json

├── vite.config.js

├── README.md

│

└── src/

&#x20;   ├── main.jsx

&#x20;   ├── App.jsx

&#x20;   │

&#x20;   ├── components/

&#x20;   │   ├── Navbar.jsx

&#x20;   │   ├── PcapUpload.jsx

&#x20;   │   ├── Dashboard.jsx

&#x20;   │   ├── SecurityScore.jsx

&#x20;   │   ├── ProtocolSummary.jsx

&#x20;   │   └── FindingsTable.jsx

&#x20;   │

&#x20;   ├── services/

&#x20;   │   └── api.js

&#x20;   │

&#x20;   ├── mock/

&#x20;   │   └── mockResult.js

&#x20;   │

&#x20;   └── styles/

&#x20;       └── App.css

