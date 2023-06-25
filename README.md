# CrowdStrike Idenity Protection Integration for Cortex XSOAR (aka Demisto):
Author: Joshua Kelley
Version: 1.0.0

# Overview:

## Use Cases:
- Pulling incidents from CrowdStrike Identity Protection API into Cortex XSOAR

## Configuration Steps:
1. Navigate to **Settings** > **Integrations** and click **BYOI**.
2. Copy the content of [this file](FIXME) into the Integration coding area.
3. Name the integration **Falcon-IdentityProtection**.
   1. Select **Fetches incidents**.
4. Create **two** Parameters:
   1. Name **credentials**: 
      1. Set **type** to Authentication and set to mandatory.
      2. **Display username**: Client ID and set show to true.
      3. **Display password**: Secret and set show to true.
   2. Name **incidentFetchinterval**:
      1. Set **type** to Short Text and set to mandatory.
      2. Set **initial value** to 1. (Indicating 1 minute interval)
      3. Set **Displayname** to "Interval to fetch incidents at in minutes.".
      4. Set **Additional information** to "The Interval at which incidents will be fetched from CrowdStrike Identity Protection (Set this to be the same as the rest of XSOAR for fetching incidents, or you'll get duplicates)."
5. Add **Command(s)**
   1. `identity-fetch-incidents` - This command will allow you to manually fetch incident details and post them to the War Room or playground.
   2. You do not need to add `test-module` as a command since its used by default with the test button in the integration settings, and `fetch-incidents` is used by default to fetch in the integration settings.
6. Also, you will need to use a Docker image that has the **crowdstrike-falconpy** python module installed. 
   1. You can use a command like this to build your own image: 
   2. `/docker_image_create name={NAME HERE} base="demisto/python3-VERSION" dependencies="crowdstrike-falconpy"` 
      1. (Replace {NAME HERE} with the name you want to give the image, and VERSION with the version of the demisto/python3 image you want to use as a base)

## Other Requirements:
You will need to also create a CrowdStrike API Client ID and Secret, and add them to the integration settings.

### Incident Objects:
The following incident objects need to be created in order for the integration to work properly:
- **Incident Type**
- **Layout**
- **Mapper**
- **Classifier**

# TODO: