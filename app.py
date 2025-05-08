from flask import Flask, request, abort
import hmac
import hashlib

app = Flask(__name__)

# Replace with your GitHub webhook secret
GITHUB_SECRET = b'secret123'

@app.route('/')
def home():
    return "Webhook server is running"

@app.route('/github-webhook/', methods=['POST'])
@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    event_type = request.headers.get('X-GitHub-Event', '')

    if event_type == 'ping':
        print("Received ping event")
        return 'Pong!', 200

    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return 'Signature missing', 400

    try:
        sha_name, received_signature = signature.split('=')
    except ValueError:
        return 'Malformed signature', 400

    if sha_name != 'sha256':
        return 'Unsupported hash type', 400

    raw_body = request.get_data()
    mac = hmac.new(GITHUB_SECRET, msg=raw_body, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()

    if not hmac.compare_digest(expected_signature, received_signature):
        print("Invalid signature")
        print("Expected:", expected_signature)
        print("Received:", received_signature)
        return 'Invalid signature', 400

    print("Webhook received and verified!")
    print("Event Type:", event_type)
    print("Payload:", raw_body.decode('utf-8'))

    return 'Success', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) # ✅ <-- Only this line changed
