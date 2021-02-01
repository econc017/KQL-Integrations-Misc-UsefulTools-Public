import datetime
import json
import logging
import sys
import urllib
import uuid

import msal
import requests

# TODO: Import the securityinsight module and change the API calls accordingly

"""Enable / Disable logging"""
# logging.basicConfig(level=logging.DEBUG)


# FIX: 'Status' need to be changed to "New" before pushing to production
# ConfigSentinel is the JSON for # ConfigSentinel is the JSON for sentinelPost(configSentinel, ...)
def sentinelPost(configSentinel, alerts):
    # Create a preferably long-lived app instance which maintains a token cache.
    app = msal.ConfidentialClientApplication(
        configSentinel["client_id"], authority=configSentinel["authority"],
        client_credential=configSentinel["secret"],
        # token_cache=...  # Default cache is in memory only.
        # How to use SerializableTokenCache: https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
    )
    # The pattern to acquire a token looks like this.
    result = None

    # Firstly, looks up a token from cache...
    # Since we are looking for token for the current app, NOT for an end user,
    # notice the account parameter is None.
    result = app.acquire_token_silent(configSentinel["scope"], account=None)

    if not result:
        logging.info(
            "No suitable token exists in cache. Let's get a new one from AAD.")
        result = app.acquire_token_for_client(scopes=configSentinel["scope"])

    if "access_token" in result:
        # Posting to sentinel
        alertCount = 0
        for alert in json.loads(alerts):
            guid = str(uuid.uuid4())
            incident_url = configSentinel["endpoint"] + "/subscriptions/" + \
                configSentinel["subscription"] + \
                "/resourcegroups/" + configSentinel["resourcegroup"] + \
                "/providers/microsoft.operationalinsights/workspaces/" + \
                configSentinel["workspace"] + \
                "/providers/Microsoft.SecurityInsights/incidents/$" + \
                guid + "/?api-version=2019-01-01-preview"

            # FIX: 'Status' need to be changed to "New" before pushing to production
            test_json = {
                "etag": guid,
                "properties": {
                    "additionalData": {
                        "alertsCount": 1,
                        "bookmarksCount": 0,
                        "commentsCount": 0,
                        "alertProductNames": [
                            "MDATP"
                        ],
                        "tactics": [alert["Category"]]
                    },
                    "classification": "Undetermined",
                    "createdTimeUtc": alert["AlertTime"],
                    "description": alert["Description"],
                    "labels": [
                        {
                            "LabelName": "MDATP_Alert"
                        },
                        {
                            "LabelName": alert["Category"]
                        }
                    ],
                    "severity": alert["Severity"],
                    "status": "Closed",
                    "title": alert["AlertTitle"]
                }
            }

            put_response = requests.put(incident_url, headers={
                'Authorization': 'Bearer ' + result['access_token']}, json=test_json)

            alertCount += 1
            print("Post result: ")
            print(put_response.json())
        print(f"Total number of alerts pushed to Sentinel: {alertCount}")
    else:
        print(result.get("error"))
        print(result.get("error_description"))
        # You may need this when reporting a bug
        print(result.get("correlation_id"))


def sentinelGet(configSentinel, minutes_ago):
    """Queries a Sentinel instance for any incidents marked as "NEW" within a specific time frame.

    :param configSentinel: Configuration JSON file with the necessary Sentinel information. Passed during execution of script through the terminal.
        {
        "authority": "https://login.microsoftonline.us/DOMAIN.COM",
        "client_id": "s6r***",
        "scope": [
            "https://management.usgovcloudapi.net/.default"
        ],
        "secret": "e6F***",
        "endpoint": "https://management.usgovcloudapi.net",
        "subscription": "v3b***",
        "resourcegroup": "rg***",
        "workspace": "wsrg***"
        }
    :param minutes_ago: Minutes to look back from the moment of execution.

    :return:
        - A successful request contains a JSON formatted list of 'new' incidents.
        - An "error" would indicate the application token was not successfully created. "error_description" expands on why.
    """
    # Create a preferably long-lived app instance which maintains a token cache.
    app = msal.ConfidentialClientApplication(
        configSentinel["client_id"], authority=configSentinel["authority"],
        client_credential=configSentinel["secret"],
        # token_cache=...  # Default cache is in memory only.
        # How to use SerializableTokenCache: https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
    )
    # The pattern to acquire a token looks like this.
    result = None

    # Firstly, looks up a token from cache...
    # Since we are looking for token for the current app, NOT for an end user,
    # notice the account parameter is None.
    result = app.acquire_token_silent(configSentinel["scope"], account=None)

    if not result:
        logging.info(
            "No suitable token exists in cache. Let's get a new one from AAD.")
        result = app.acquire_token_for_client(scopes=configSentinel["scope"])

    if "access_token" in result:
        incident_url = configSentinel["endpoint"] + "/subscriptions/" + \
            configSentinel["subscription"] + \
            "/resourcegroups/" + configSentinel["resourcegroup"] + \
            "/providers/microsoft.operationalinsights/workspaces/" + \
            configSentinel["workspace"] + \
            "/providers/Microsoft.SecurityInsights/incidents?api-version=2019-01-01-preview"

        time = datetime.datetime.utcnow()
        # How many minutes back to look
        ago = time - datetime.timedelta(minutes=minutes_ago)
        query = "$filter=" + urllib.parse.quote_plus(
            "(properties/status eq 'New') and (properties/createdTimeUtc le ") + urllib.parse.quote_plus(time.strftime("%Y-%m-%dT%H:%M.%SZ")) + " and " + "properties/createdTimeUtc ge " + urllib.parse.quote_plus(ago.strftime("%Y-%m-%dT%H:%M.%SZ")) + ")"
        get_response = requests.get(incident_url, headers={
            'Authorization': 'Bearer ' + result['access_token']}, params=query).json()
        return json.dumps(get_response, indent=2)
    else:
        print(result.get("error"))
        print(result.get("error_description"))
        # You may need this when reporting a bug
        print(result.get("correlation_id"))


def main():
    # time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M.%SZ")
    # print(time)
    sentinelIncidents = sentinelGet(json.load(open(sys.argv[1])), 10)
    print(sentinelIncidents)


if __name__ == "__main__":
    main()
