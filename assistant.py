from openai import OpenAI
import json

##########
##########
# Vars

# Get these variables from your OpenAI Assistant. Hide these in an .env file during deployment.
OPENAI_API_KEY = ""
OPENAI_ASSISTANT_ID = ""

# Define your instructions here based on your use case. Here is something basic to get you going.
BASE_INSTRUCTIONS = '''
    You're a security expert acting as a SOC Analyst. Analyze the provided alert and context for malicious activity.
    When you receive an input and output from an alert, you'll return a JSON object with the following keys:

    - summary (str): A brief summary of the analysis done on the alert and any items that stand out as supicious, remove suspicion, or are unknown. Keep this less than 300 characters.
    - recommendation (str): A recommendation whether it is safe to close the ticket, investigate more into the ticket (outcome is unknown based on the data given), or escalate to a security incident (confidence is high this is a security risk) with a reasoning on why based on what was found in the alert or triage context. Keep this recommendation brief and to the point.
    - classification (str): a recommended classification for Jira (True Positive, False Positive, Expected Activity, Confirmed Activity)
    - severity (int): A score of 1-10 on how severe the files shared are in relation to company intellectual property (10 being very high risk, sensitive items)
    - confidence (int): A score 1-10 on the probability this is a true positive (10 very positive)
    - artifacts (list): Evidence that is a list of the potentially problematic/malicious artifacts found in the alert or triage context
'''
##########
##########

##########
##########
# Assistant Analyze
'''
Use this method as the main driver to construct your analysis of alerts.
'''
##########
##########
def assistant_analyze(input, log_type, detection_name):
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        my_thread = client.beta.threads.create()

        alert_context = _construct_alert_context(input)

        full_triage_instructions = _construct_full_instructions(log_type, detection_name)

        if alert_context != "Could not create user content":
            my_thread_message = client.beta.threads.messages.create(
                thread_id=my_thread.id,
                role="user",
                content=alert_context
            )

            dart_assistant = client.beta.threads.runs.create(
                thread_id=my_thread.id,
                assistant_id=OPENAI_ASSISTANT_ID,
                instructions=full_triage_instructions
            )

            while dart_assistant.status in ("queue", "in_progress"):
                keep_retrieving_run = client.beta.threads.runs.retrieve(
                    thread_id=my_thread.id,
                    run_id=dart_assistant.id
                )

                if keep_retrieving_run.status == "completed":
                    all_messages = client.beta.threads.messages.list(
                        thread_id=my_thread.id,
                    )

                    analysis = all_messages.data[0].content[0].text.value
                    json_analysis = json.loads(analysis)

                    return json_analysis
                elif keep_retrieving_run.status == "queued" or keep_retrieving_run.status == "in_progress":
                    pass
                else:
                    print("An error occurred while analyzing the alert:", keep_retrieving_run.last_error)
                    return "An error occurred while analyzing the alert"
        else:
            return "An error occurred trying to construct an analysis to the given alert."
    except Exception as e:
        print("An exception occurred analyzing the alert:", e)
        return "An exception occurred analyzing the alert"

##########
##########
# Construct Alert Context
'''
Use this method to construct the context of the alert in text form.
'''
##########
##########

def _construct_alert_context(input):
    # Change the path of different variables as your SIEM dictates
    alert_title = input.get('title', 'unknown title')
    detection_name = input.get('name' 'unknown detection')
    description = input.get('description', 'unknown description')
    runbook = input.get('runbook', 'unknown runbook')

    content = f'''
    An alert came in titled: {alert_title}. It comes from a detection names {detection_name}.

    The description is: {description}
    It has a runbook with the following instructions: {runbook}

    The following is the raw json of the alert. Included is the automated recon don eon the alert artifacts.
    Return an analysis in json:
    {input}
    '''

    return content

##########
##########
# Construct Full Instructions
'''
Use this method to construct log type and detection specific triage instructions.

The implementation here is basic. Break out this logic into separate files as it starts to grow.
'''
##########
##########

def _construct_full_instructions(log_type, detection_name):
    additional_prompt = ""

    if log_type == "Logtype.A":
        if detection_name == "Detection1":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."
        elif detection_name == "Detection2":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."
    elif log_type == "Logtype.B":
        if detection_name == "Detection3":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."
        elif detection_name == "Detection4":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."
    elif log_type == "Logtype.C":
        if detection_name == "Detection5":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."
        elif detection_name == "Detection6":
            additional_prompt = "Add additional instructions here based on artifacts collected in triage."

    return f"{BASE_INSTRUCTIONS}\n{additional_prompt}"
