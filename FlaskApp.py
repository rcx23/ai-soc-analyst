from flask import Flask, request, jsonify
from assistant import assistant_analyze

app = Flask(__name__)

##
# Keys for proper use of the assistant method.
#####
alert_key = "alert"
log_type_id = "LogType"
detection_name = "detection_name"

@app.route("/main", methods=['POST'])
def main():
    payload = request.get_json()

    if not payload:
        return jsonify({'error' : "no input provided"}), 400

    if payload.get(log_type_id, 'no_log_type') != 'no_log_type':
        alert = payload[alert_key]
        log_type = payload[log_type_id]
        detection = payload[detection_name]

        return assistant_analyze(alert, log_type, detection)
    else:
        return jsonify({'error': True}), 400

if __name__ == '__main__':
    app.run(port=500)