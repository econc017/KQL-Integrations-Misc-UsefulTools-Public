### name
	* Call Pwsh From Cmd
### description
  * 'Calling Powershell from Cmd, Sometimes adversaries will call powershell commands from a regular command prompt. This is often never done by System Administrators as they would just opt to run powershell rather than cmd. But when using custom built tools cmd will be the main option of choice.'
### severity
	* Medium
### enabled
	* false
### requiredDataConnectors
	* connectorId
		- SecurityEvents
    * dataTypes
		- SecurityEvent
### queryFrequency
	* 5m
### queryPeriod
	* 5m
### triggerOperator
	* gt
### triggerThreshold
	* 0
### tactics
  - Execution
### relevantTechniques
  - T1047
