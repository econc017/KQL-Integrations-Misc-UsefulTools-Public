### name 
   * Adding Hidden File Attribute via Attrib
### description
```
Users can mark specific files as hidden by using the attrib.exe binary. Simply do attrib +h filename to mark a file or folder as hidden. Similarly,
the "+s" marks a file as a system file and the "+r" flag marks the file as read only. Like most windows binaries,
the attrib.exe binary provides the ability to apply these changes recursively "/S"
```
### severity
    * Medium
### enabled 
    * false
### requiredDataConnectors
    * connectorId
        - SecurityEvents
    * dataTypes:
        - SecurityEvent
### queryFrequency
    * 5m
### queryPeriod
    * 5m
### triggerOperator
    * gt
### triggerThreshold 
    * 0
### tactics:
  * DefenseEvasion
  * Persistence
### relevantTechniques:
  * TA0005
  * T1158
  * TA0003
