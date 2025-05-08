from flask import Flask, request, abort
import hmac
import hashlib

app = Flask(__name__)
GITHUB_SECRET = b'secret123' # Replace with your GitHub webhook secret

@app.route('/')
def home():
    return "Hello"

@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    event_type = request.headers.get('X-GitHub-Event', '')

    # If it's a ping event, skip signature check
    if event_type == 'ping':
        return 'Pong!', 200

    # For other events, validate signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return 'Signature missing', 400

    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return 'Unsupported hash type', 400

    mac = hmac.new(GITHUB_SECRET, msg=request.data, digestmod=hashlib.sha256)
    if not hmac.compare_digest(mac.hexdigest(), signature):
        return 'Invalid signature', 400

    return 'Webhook received and verified!', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5800)
