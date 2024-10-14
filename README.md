# ai-soc-analyst

## Purpose

This FlaskApp is intended to act as the final step in a SOAR workflow. Pass in all of your SOAR artifacts and the raw alert to get the AI Analyst to perform an analysis of the alert.

## Requirements

1. An OpenAI account to spin up an Assistant.
2. A server to deploy this Flask App to.

## How to use

Run FlaskApp.py

Send a POST request to the /main route.

### Sample Payload

alert - alert is a key:value pair that encompasses the raw json from the alert that fired, and any additional data that you want to include from your SOAR workflow. Since everyone's workflow is different, you'll need to configure this to your use case.

log_type - the system that triggered the alert. This will be used to route the logic for any system specific triage instructions

detection - the name of the detection that fired. This will be used to route the logic for any detection specific triage instructions.

### Recomendations

Add an authentication to the endpoint when deploying.
