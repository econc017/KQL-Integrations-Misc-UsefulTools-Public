# Config use

The configurations let the main script know where to get tokens from, what consent should be requested from the authentication authority and what endpoint to query.

You can run the MSAL python script with a JSON configuration file by executing:
**DefenderToLogAnalytics_msal.py Defender_LogAnalytics_parameters.json**

## Configuration example
The configuration file (Defender_LogAnalytics_parameters_*.json) would look like this (excluding the // comments):

```
{
  "Defender": {
    "authority": "https://login.microsoftonline.us/Enter_the_Tenant_NAME(or ID)_Here",
    "client_id": "your_client_id(the application SIEM api app)",
    "scope": [
      "https://graph.microsoft.us/.default"
    ],
    // For more information about scopes for an app, refer:
    // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate"
    "secret": "The secret generated by AAD during your confidential app registration",
    // For information about generating client secret, refer:
    // https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Client-Credentials#registering-client-secrets-using-the-application-registration-portal
    "endpoint": "https://wdatp-alertexporter-us.securitycenter.windows.us/api/Alerts?limit=20&ago=PT30M"
  },
  "LogAnalytics": {
    "WORKSPACE_ID": "LogAnalytics_WorkspaceID",
    "WORKSPACE_SHARED_KEY": "Primary_or_Secondary_workspace_key",
    "CUSTOM_TABLE_NAME": "Desired_Custom_Table_Name"
  }
}
```

## Explanation
Defender - authority: Authentication authority that will be used to grab a token, along with the Tenant that the application will operate on. Could be in GUID format or the tenant's azure AD name.
Defender - client_id: ID of the Azure AD application.
Defender - scope: Application resource identifier which is the App's ID URI with /.default appended. This lets the authority know which resource the token should be issued for. The "/.default" scope means that the resource should return a token with the full static consent list available from the resource as listed in the application's API permissions. And example of another valid scope would be **https://graph.microsoft.us/User.Read.All**. For more information on scopes and consent go here: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#the-default-scope
Defender - secret: Azure AD application secret generated.
Defender - endpoint: Endpoint that will be queried when DefenderToLogAnalytics_msal.py is run. A different example of an endpoint to query would be: **https://wdatp-alertexporter-us.securitycenter.windows.us/api/Alerts?limit=20&ago=PT30M**

LogAnalytics - WORKSPACE_ID: Can be gathered by going to the **Azure Portal -> Log Analytics workspaces (choose the desired workspace) -> Agents management (copy Workspace ID)**.
LogAnalytics - WORKSPACE_SHARED_KEY: Can be gatehered by going to the **Azure Portal -> Log Analytics workspaces (choose the desired workspace) -> Agents management (copy Primary or Secondary key)**.
LogAnalytics - CUSTOM_TABLE_NAME: The custom table name that will be created in the log analytics workspace. The name included here will have "**_CL**" appended and will appear under the "**Custom Logs**" section. For example **"CUSTOM_TABLE_NAME": "Defender" would produce a new table named "Defender_CL"**.