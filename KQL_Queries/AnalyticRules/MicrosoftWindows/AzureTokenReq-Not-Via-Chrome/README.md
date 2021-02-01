### name
	* AzureTokenReq Not Via Chrome
### description
	* 'Technique explained here => https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/'
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
  - Persistence
  - CredentialAccess
### relevantTechniques
	*
