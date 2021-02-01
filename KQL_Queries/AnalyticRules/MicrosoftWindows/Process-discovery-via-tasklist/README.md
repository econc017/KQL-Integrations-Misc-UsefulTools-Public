Process Discovery via Tasklist
https://github.com/elastic/stack-docs/blob/7.8/docs/en/siem/detections/prebuilt-rules/rule-details/process-discovery-via-tasklist.asciidoc

Administrators may use the tasklist command to display a list of currently running processes. By itself, it does not indicate malicious activity. After obtaining a foothold, it’s possible adversaries may use discovery commands like tasklist to get information about running processes.

Windows Event ID 4688: Process creation