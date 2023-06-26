register_module_line('Falcon-IdentityProtection', 'start', __line__())
#######################
# Description: CrowdStrike Falcon API Integration - for XSOAR
# Author: Joshua Kelley
# Creation: June 2023
#######################

from falconpy import APIHarness
import json
import urllib3
from datetime import datetime, timedelta, timezone
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTEGRATION_NAME='Falcon-IdentityProtection'
CLIENT_ID = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')

# Functions

######################
# Description: Test connection to CrowdStrike Falcon API
def test_module():
    try:
        falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
        response = falcon.command("GetSensorInstallersByQuery", limit=1)
    except ValueError:
        return 'Connection Error: The URL or The API key you entered is probably incorrect, please try again.'
    return 'ok'

######################
# Description: Identity Protection API functions
# functions: GetDetections - Get CrowdStrike Identity Protection Incidents
#            IdentityProtection - Main function to call GetDetections and return XSOAR alerts
# Parameters: falcon - Falcon API Harness
# Returns: CrowdStrike API response and formatted XSOAR incident data (JSON)
######################
def GetDetections(falcon):
    fetch_inc_interval = getFetchInterval()
    GraphQL_Query = '''
        {
            incidents(createdAfter: "REPLACEME", severities: [LOW, MEDIUM, HIGH], first: 5, sortOrder: DESCENDING) {
                edges {
                    node {
                        __typename
                        incidentId
                        severity
                        type
                        lifeCycleStage
                        startTime
                        endTime
                        alertEvents {
                            alertId
                            state {
                                lifeCycleStage
                            }
                            alertType
                            timestamp
                            eventType
                            eventLabel
                            eventSeverity
                            startTime
                            endTime
                            resolved
                            entities {
                                type
                                primaryDisplayName
                                secondaryDisplayName
                                hasADDomainAdminRole
                            }
                        }
                    }
                }
            }
        }
        '''

    idp_query = GraphQL_Query.replace('REPLACEME', fetch_inc_interval)

    variables = {
        "string": "string, int, float"
    }

    BODY = {
        "query": idp_query,
        "variables": variables
    }

    response = falcon.command("api_preempt_proxy_post_graphql", body=BODY, filter="(severity:<0,severity:>=20)")
    return response

def IdentityProtection():
    falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
    response = GetDetections(falcon)
    response = response["body"]["data"]["incidents"]["edges"]
    alert_return = []
    if len(response) == 0:
        return alert_return
    for incident in response:
        if len(incident) == 0:
            return alert_return
        if incident['node']['lifeCycleStage'] == 'NEW':
            incident_data = json.dumps(incident, indent=4)
            alert_return.append({
                'name': "CS Identity Protection: " + incident['node']['type'],
                'occurred': datetime.now(timezone.utc).astimezone().isoformat(),
                'dbotMirrorId': incident['node']['incidentId'],
                'rawJSON': incident_data
                })


    return alert_return

####################
# Description: This function will create an iso formatted datetime string offset by the incidentFetchInterval
# Params: None
# Return: datetime string for the fetch interval in UTC time and iso format
# Example: 2023-06-14T15:25:00.000Z
####################
def getFetchInterval():
    tz = timezone(timedelta(hours=0), name="UTC")
    interval = demisto.params().get('incidentFetchInterval')
    current_datetime = datetime.now(tz=tz) - timedelta(minutes=int(interval))
    formatted_datetime = current_datetime.isoformat(timespec='milliseconds')
    formatted_datetime = formatted_datetime.replace('+00:00', 'Z')
    return formatted_datetime

######################
#    Main function   #
######################
def main():
    command = demisto.command()
    try:
        if command == 'test-module':
            result = test_module()
            return_results(result)
        elif command == 'fetch-incidents':
            demisto.incidents(IdentityProtection())
        elif command== 'identity-fetch-incidents':
            return_results(IdentityProtection())
        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))
    pass

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

register_module_line('Falcon-IdentityProtection', 'end', __line__())
