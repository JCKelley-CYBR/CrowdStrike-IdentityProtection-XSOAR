register_module_line('Falcon-IdentityProtection', 'start', __line__())
#######################
# Description: CrowdStrike Falcon API Integration for XSOAR
# Author: Joshua Kelley
# Creation: June 2023
#######################
# V1 - 2023-06-15 - Initial Release
# V1.5 - 2023-06-16 - Added Identity Protection
# V2 - 2023-06-23 - Fixed SpyBarron function to use QueryDevicesByFilterScroll and adhere to CS API limits
# V3 - 2023-07-03 - Added Identity Protection Incident Set State function
# V4 - 2023-10-04 - Added watchlist functions

from falconpy import APIHarness
import json
import urllib3
from datetime import datetime, timedelta, timezone
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTEGRATION_NAME='Falcon-IdentityProtection'
CLIENT_ID = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')
# Update with your falcon instance us-1 or us-2
INCIDENT_URL = "https://falcon.us-(1|2).crowdstrike.com/identity-protection/incidents/"

# Functions

######################
# Description: Test connection to CrowdStrike Falcon API
# Parameters: None
# Returns: Success or Failure message to Demisto
######################
def test_module():
    try:
        falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
        response = falcon.command("GetSensorInstallersByQuery", limit=1)
    except ValueError:
        return 'Connection Error: The URL or The API key you entered is probably incorrect, please try again.'
    return 'ok'

######################
# Description: Identity Protection functions
# functions: GetDetections - Get Identity Protection detections from CrowdStrike
#            IdentityProtection - Main function to call GetDetections
#            getFetchInterval - Get the current time minus the fetch interval
#            identitySetIncident - Set the incident state in CrowdStrike Identity Protection, takes action and reason as parameters
# Parameters:
# Returns: CrowdStrike Identity Protection Incidents from the last fetch interval
######################


######################
# Description: Query CrowdStrike Identity Protection for incidents matching GraphQL query
# Parameters: falcon - Falcon API Harness
# Returns: CrowdStrike Identity Protection API response
######################
def GetDetections(falcon):
    fetch_inc_interval = getFetchInterval()
    # incident query can be updated to use updatedAfter instead of createdAfter in order 
    # to capture incidents that have been updated, however this will also capture incidents
    # that have been updated by the user and not just the system.
    GraphQL_Query = '''
        {
            incidents(updatedAfter: "REPLACEME", severities: [MEDIUM, HIGH], first: 5, sortOrder: DESCENDING) {
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
                            __typename
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
                            relatedEvents(first: 10) {
                                nodes {
                                    eventType
                                    timestamp
                                    eventId
                                    ... on TimelineUserOnEndpointActivityEvent {
                                        userEntity {
                                            __typename
                                            primaryDisplayName
                                            secondaryDisplayName
                                            emailAddresses
                                            mostRecentActivity
                                            accounts {
                                                __typename
                                                enabled
                                                description
                                                dataSource
                                            }
                                        }
                                        endpointEntity {
                                            __typename
                                            primaryDisplayName
                                            hostName
                                            mostRecentActivity
                                            agentId
                                            lastIpAddress
                                            staticIpAddresses
                                            operatingSystemInfo {
                                                __typename
                                                displayName
                                                version
                                                servicePack
                                                target
                                                name
                                            }
                                        }
                                        targetEntity {
                                            primaryDisplayName
                                            ... on EndpointEntity {
                                                hostName
                                                mostRecentActivity
                                                agentId
                                                lastIpAddress
                                                staticIpAddresses
                                                operatingSystemInfo {
                                                    __typename
                                                    displayName
                                                    version
                                                    servicePack
                                                    target
                                                    name
                                                }
                                            }
                                        }
                                    }
                                }
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

######################
# Description: Retrieve Identity Protection Incidents from CrowdStrike
# Parameters: None
# Returns: Identity Protection Incidents from CrowdStrike and formatted for XSOAR
######################
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
                'name': "CS Identity Protection: " + incident['node']['incidentId'] + " " + incident['node']['type'],
                'occurred': datetime.now(timezone.utc).astimezone().isoformat(),
                'dbotMirrorId': incident['node']['incidentId'],
                'rawJSON': incident_data
                })
    return alert_return

######################
# Description: Set the incident state in CrowdStrike Identity Protection
# Parameters: action - action taken on the incident (CLOSED, IGNORED, etc)
#             reason - reason for the action taken
# Returns: CrowdStrike API response
######################
def identitySetIncident(action, reason, eventid):
    # eventid = demisto.incidents()[0]['eventid']

    falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)

    GraphQL_Query = '''mutation {
                        setIncidentState(
                                input: {
                                    lifeCycleStage: ACTION_TAKEN
                                    incidentId: "NUMBER"
                                    reason: "REASON"
                                }
                            ) {
                                incident {
                                    lifeCycleStage
                                }
                            }
                        }
    '''
    idp_query_action = GraphQL_Query.replace('ACTION_TAKEN', action)
    idp_query_number = idp_query_action.replace('NUMBER', eventid)
    idp_query = idp_query_number.replace('REASON', reason)

    variables = {
        "string": "string, int, float"
    }

    BODY = {
        "query": idp_query,
        "variables": variables
    }

    response = falcon.command("api_preempt_proxy_post_graphql", body=BODY)
    return response

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
# Description: Set the watchlist value for a user in CrowdStrike Identity Protection to True
# Parameters: id - samAccountName for the user to add to the watchlist
# Returns: CrowdStrike API response
######################
def identityAddWatchList(falcon, id):
    GraphQL_Query = '''mutation watchSomeUser {
        addEntitiesToWatchList(input: { 
            entityQuery: {
                    samAccountNames: "REPLACEME"
                }
            })
            {
                updatedEntities
                {
                    primaryDisplayName
                    secondaryDisplayName
                    watched
                }
                failures
                {
                    entityIds
                    errorDetails
                    {
                        message
                    }
                }
            }
    }'''

    idp_query = GraphQL_Query.replace('REPLACEME', id)

    variables = {
        "string": "string, int, float"
    }

    BODY = {
        "query": idp_query,
        "variables": variables
    }

    response = falcon.command("api_preempt_proxy_post_graphql", body=BODY)
    return response

######################
# Description: Set the watchlist value for a user in CrowdStrike Identity Protection to False
# Parameters: id - samAccountName for the user to remove from the watchlist
# Returns: CrowdStrike API response
######################
# Requies the DOMAINHERE to be updated with your own domain name(s)
def identityRemoveWatchList(falcon, id):
    GraphQL_Query = '''mutation unwatchSomeUser {
        removeEntitiesFromWatchList(input: { 
            entityQuery: {
                    secondaryDisplayNames: "DOMAINHERE\\\\REPLACEME"
                }
            })
            {
                updatedEntities
                {
                    primaryDisplayName
                    secondaryDisplayName
                    watched
                }
                failures
                {
                    entityIds
                    errorDetails
                    {
                        message
                    }
                }
            }
    }'''

    idp_query = GraphQL_Query.replace('REPLACEME', id)

    variables = {
        "string": "string, int, float"
    }

    BODY = {
        "query": idp_query,
        "variables": variables
    }

    response = falcon.command("api_preempt_proxy_post_graphql", body=BODY)
    return response

######################
# Description: Add a list of users to the watchlist in CrowdStrike Identity Protection - Loops through a list of samAccountNames
# Parameters: ids - list of samAccountNames to add to the watchlist
# Returns: Success or Failure message
######################
def watchList(action, ids):
    falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
    status = 'Success'
    ids = ids.split(',')
    for id in ids:
        if action == "add":
            response = identityAddWatchList(falcon, id)
        elif action == "remove":
            response = identityRemoveWatchList(falcon, id)
        else:
            return 'Failure, invalid action'
        print(response['body'])
        if response['status_code'] != 200:
            status = 'Failure'
    return status

######################
# Description: Main function
# Parameters: None
# Returns: Success or Failure message to Demisto console/playground
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
        elif command == 'Falcon-SetIncident':
            return_results(identitySetIncident(demisto.args()['action'], demisto.args()['reason'], demisto.args()['eventid']))
        elif command == 'Falcon-AddWatchList':
            return_results(watchList("add", demisto.args()['id']))
        elif command == 'Falcon-RemoveWatchList':
            return_results(watchList("remove", demisto.args()['id']))
        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))
    pass

if __name__ in ('__main__', 'builtin', 'builtins'):
    main()

register_module_line('Falcon-IdentityProtection', 'end', __line__())