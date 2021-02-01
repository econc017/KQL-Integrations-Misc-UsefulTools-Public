# AWS Alert progress

| Severity 	| Name                                                                  	| Tactics                                                            	| Comments 	| Done 	|
|----------	|-----------------------------------------------------------------------	|--------------------------------------------------------------------	|----------	|------	|
| High      | Known IRIDIUM IP                                                          | Command and Control                                                   |           |  [x]  |
| Medium   	| Full Admin policy created and then attached to Roles, Users or Groups 	| Privilege Escalation                                               	|          	|  [x] 	|
| Medium   	| Failed AzureAD logons but success logon to AWS Console                	| Initial Access,Credential Access                                   	|          	|  [x] 	|
| Medium   	| Failed AWS Console logons but success logon to AzureAD                	| Initial Access, Credential Access                                  	|          	|  [x] 	|
| Medium   	| MFA disabled for a user                                               	| Credential Access                                                  	|          	|  [x] 	|
| Medium    | TI map IP entity to AWSCloudTrail                                         | Impact                                                                |           |  [x]  |
| Low      	| Changes to AWS Security Group ingress and egress settings             	| Persistence                                                        	|          	|  [x] 	|
| Low      	| Monitor AWS Credential abuse or hijacking                             	| Discovery                                                          	|          	|  [x] 	|
| Low      	| Changes to AWS Elastic Load Balancer security groups                  	| Persistence                                                        	|          	|  [x] 	|
| Low      	| Changes to Amazon VPC settings                                        	| Privilege Escalation, Lateral Movement                             	|          	|  [x] 	|
| Low      	| New UserAgent observed in last 24 hours                               	| Initial Access, Command and Control, Execution                     	|          	|  [x] 	|
| Low      	| Login to AWS Management Console without MFA                           	| Defense Evasion, Privilege Escalation, Persistence, Initial Access 	|          	|  [x] 	|
| Low      	| Changes to internet facing AWS RDS Database Instances                 	| Persistence                                                        	|          	|  [x] 	|
| Low      	| Changes made to AWS CloudTrail logs                                   	| Defense Evasion                                                    	|          	|  [x] 	|
| Low       | AWS EventRule AssociateRouteTable                                         | Discovery                                                             |           |  [x]  |
| Low       | AWS EventRule AttachClassicLinkVpc                                        | Defense Evasion                                                       |           |  [x]  |
| Low       | AWS EventRule AttachGroupPolicy                                           | Persistence                                                           |           |  [x]  |
| Low       | AWS EventRule AttachInternetGateway                                       | Exfiltration                                                          |           |  [x]  |