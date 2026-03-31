FILE_SCAN_PROMPT = "User uploaded a file named {filename}. Explain if it's malicious and provide MITRE ATT&CK info."
URL_SCAN_PROMPT = "Analyze this URL: {url}. Summarize if it's malicious and include any indicators or MITRE tags."
HASH_CHECK_PROMPT = "Check the following hash: {hash}. See if it exists in our database or public malware datasets."
THREAT_EXPLAIN_PROMPT = "Explain the threat behavior and MITRE ATT&CK techniques for {malware_name}."