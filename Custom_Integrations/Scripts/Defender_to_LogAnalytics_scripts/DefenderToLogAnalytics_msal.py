import base64
import datetime
import hashlib
import hmac
import json
import logging
import sys
import time

import msal
import requests
from tqdm import tqdm

"""Enable / Disable logging"""
# logging.basicConfig(level=logging.DEBUG)


def defenderGet(configDefender):
    """Queries for defender alerts.

    :param configDefender: Configuration JSON file with Defender information, and alert query.
        {
            "Defender": {
                "authority": "https://login.microsoftonline.us/DOMAIN.COM",
                "client_id": "36c***",
                "scope": [
                "https://graph.windows.net/.default"
                ],
                "secret": "JFc***",
                "endpoint": "https://wdatp-alertexporter-us.securitycenter.windows.us/api/Alerts?limit=20&ago=PT30M"
            },
            "LogAnalytics": {
                "WORKSPACE_ID": "338***",
                "WORKSPACE_SHARED_KEY": "Yui5***",
                "CUSTOM_TABLE_NAME": "DefenderAlertTest"
            }
        }
    :return: A JSON formatted file with all (or none) alerts returned from query.
        - A successful response would contain either 0 or more alerts formatted as JSON.
        - An "error" would indicate the application token was not successfully created. "error_description" expands on why.
    """
    # Create a preferably long-lived app instance which maintains a token cache.
    app = msal.ConfidentialClientApplication(
        configDefender["Defender"]["client_id"], authority=configDefender["Defender"]["authority"],
        client_credential=configDefender["Defender"]["secret"],
        # token_cache=...  # Default cache is in memory only.
        # How to use SerializableTokenCache: https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
    )

    # The pattern to acquire a token looks like this.
    result = None

    # Firstly, looks up a token from cache...
    # Since we are looking for token for the current app, NOT for an end user,
    # notice the account parameter is None.
    result = app.acquire_token_silent(
        configDefender["Defender"]["scope"], account=None)

    if not result:
        logging.info(
            "No suitable token exists in cache. Let's get a new one from AAD.")
        result = app.acquire_token_for_client(
            scopes=configDefender["Defender"]["scope"])

    if "access_token" in result:
        # Calling graph using the access token
        graph_data = requests.get(  # Use token to call downstream service
            configDefender["Defender"]["endpoint"],
            headers={'Authorization': 'Bearer ' + result['access_token']}, ).json()
        # print("Graph API call result: ")
        # print(json.dumps(graph_data, indent=2))
        return json.dumps(graph_data, indent=2)
    else:
        print(result.get("error"))
        print(result.get("error_description"))
        # You may need this when reporting a bug
        print(result.get("correlation_id"))


def build_signature(WORKSPACE_ID, WORKSPACE_SHARED_KEY, date, content_length, method, content_type, resource):
    logging.info("Building the API signature")
    """Helper method to build the request signature.

    Requests to the Azure monitor HTTP Data Collector API need an authorization header.
    To authenticate the request, it must be signed with the primary or secondary key for the workspace.

    :param WORKSPACE_ID: Workspace ID of the log analytics workspace.
    :param WORKSPACE_SHARED_KEY: Workspace primary or secondary key.
    :param date: RFC1123 date that the data will be posted with.
    :param content_length: Total length of JSON to post.
    :param method: HTTP method to be used. Most likely POST.
    :param content_type: Type of data to be sent. Most likely application/json.
    :param resource: Resource to query endpoint for. In the case of POSTing to log analytics it would be /api/logs.

    :return:
        A string in the format "SharedKey <WorkspaceID>:<hmac-sha256_encoded_key>".
    """
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(WORKSPACE_SHARED_KEY)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {WORKSPACE_ID}:{encoded_hash}"
    return authorization


def post_data(WORKSPACE_ID, WORKSPACE_SHARED_KEY, body, LOG_TYPE):
    logging.info("Posting data to Azure Log analytics workspace")
    """Builds and sends request to the Azure monitor HTTP Data Collector API.
    
    Posts the JSON document to Azure Log Analytics.
    Uses the build_signature() method to build the signature to be used for authorization in headers.
    Prints the response status code upon completion.

    Data Limits:
        Maximum 30MB per post.
        Maximum 32KB for field values.
        Recommended max 50 fields.
        Maximum 500 characters per column.

    :param WORKSPACE_ID: Workspace ID of the log analytics workspace.
    :param WORKSPACE_SHARED_KEY: Workspace primary or secondary key.
    :param body: JSON to send to log analytics.
    :param LOG_TYPE: Custom table name for the data.
    """
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(WORKSPACE_ID, WORKSPACE_SHARED_KEY,
                                rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + WORKSPACE_ID + '.ods.opinsights.azure.us' + \
        resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': LOG_TYPE,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    print(response.status_code)


# Commented out the post_data() execution for testing, uncomment it for the post to work.
def main():
    # This is the configuration file with all of the keys
    config_file = json.load(open(sys.argv[1]))

    # alerts is initiated with resuls of the Defender Alerts query
    alerts = defenderGet(config_file)
    if len(alerts) != 2:
        # A Json is created from each result and posted to Azure Log Analytics
        for alert in tqdm(json.loads(alerts)):
            time.sleep(0.001)
            body = json.dumps(alert)
            #post_data(config_file["LogAnalytics"]["WORKSPACE_ID"], config_file["LogAnalytics"]["WORKSPACE_SHARED_KEY"], body, config_file["LogAnalytics"]["CUSTOM_TABLE_NAME"])
    else:
        print("--- No Alerts ---")


if __name__ == "__main__":
    main()
