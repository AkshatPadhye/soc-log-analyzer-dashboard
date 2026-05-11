# SOC-log-analyzer-dashboard
This repository hosts a Log Analyzer Dashboard designed for cybersecurity monitoring and SOC (Security Operations Center) analysis. It provides a centralized, scalable, and analyst‑friendly platform for ingesting, parsing, visualizing, and investigating security‑relevant logs across diverse environments. Built for real‑time awareness and rapid incident response, the dashboard helps SOC teams transform raw log data into actionable intelligence.

The system supports log collection from multiple sources, including firewalls, endpoint agents, IDS/IPS tools, cloud workloads, authentication systems, and application services. A flexible parsing pipeline normalizes logs into a consistent schema, enabling correlation across different technologies and vendors. The repository includes modular parsers, enrichment functions, and threat‑detection logic that can be easily extended to match organizational needs.

Dashboards provide clear visibility into patterns such as authentication anomalies, lateral movement attempts, network scanning behavior, unusual process execution, data exfiltration indicators, and privilege‑escalation events. Visualizations highlight trends over time, high‑risk IPs, top alerts, geolocation insights, and deviations from historical baselines. Analysts can pivot from aggregated metrics into raw event logs for deep investigation.

A rule‑based and behavioral analytics engine supports detection of known attack signatures as well as subtle suspicious activity. Integration with threat‑intelligence feeds enables automatic tagging of malicious domains, hashes, and IP addresses. Alert workflows allow analysts to triage events, add annotations, assign severity levels, and track remediation steps.

The repository is structured for easy deployment in both small labs and large enterprise settings. It supports containerized deployment using Docker or Kubernetes, with optional connectors for Elasticsearch, Splunk, OpenSearch, Kafka, and other log pipelines. Configuration files and sample datasets are included to help new users get started quickly.

Security and performance are prioritized: role‑based access control, secure API endpoints, and efficient data‑stream handling ensure safe and reliable operation even under heavy log volume. The codebase emphasizes clarity and maintainability, making it suitable for SOC teams, cybersecurity students, researchers, and organizations building their own monitoring stack.

Overall, this Log Analyzer Dashboard provides a comprehensive, extensible foundation for continuous monitoring, threat detection, and investigative workflows within modern cybersecurity operations.




<img width="1920" height="1020" alt="2026-05-11 (19)" src="https://github.com/user-attachments/assets/9db73b5b-c9cd-41e2-ae69-296ac11f13e0" />
<img width="1920" height="1020" alt="2026-05-11 (17)" src="https://github.com/user-attachments/assets/42172462-ad9d-4348-ad2d-2cd1741d1e10" />
<img width="1920" height="1020" alt="2026-05-11 (16)" src="https://github.com/user-attachments/assets/6891f84e-0796-4260-b8e9-9b9b6aadbf3d" />

