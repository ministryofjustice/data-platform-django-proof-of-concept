from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
import os
import requests
import json

# Load secrets from a JSON file
with open('secrets.json') as f:
    secrets = json.load(f)

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'something-secret'  # Change this to a random secret key

# Azure AD OAuth configuration
oauth = OAuth(app)
azure = oauth.register(
    'azure',
    client_id=secrets['client_id'],
    client_secret=secrets['client_secret'],
    server_metadata_url=f'https://login.microsoftonline.com/{secrets["tenant_id"]}/v2.0/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile User.ReadWrite.All Group.ReadWrite.All offline_access',
    },
)

@app.route('/')
def homepage():
    user_info = session.get('user')
    groups = session.get('groups')
    if user_info:
        # User is logged in, render the dashboard
        return render_template('dashboard.html', user_info=user_info, groups=groups)
    # For logged-out users, render the homepage
    return render_template('homepage.html')

@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return azure.authorize_redirect(redirect_uri)

@app.route('/login/authorized')
def authorized():
    token = azure.authorize_access_token()
    user_resp = azure.get('https://graph.microsoft.com/v1.0/me', token=token)
    user_info = user_resp.json()

    # Debug: Print the whole response to see all available fields
    print("\nUser response:")
    print(json.dumps(user_info, indent=4))  # Pretty-print the JSON response

    session['user'] = user_info

    # Attempt to get the user's group memberships
    try:
        groups_resp = azure.get('https://graph.microsoft.com/v1.0/me/memberOf', token=token)
        groups_info = groups_resp.json()

        # Debug: Print the groups response
        print("\nGroups response:")
        print(json.dumps(groups_info, indent=4))  # Pretty-print the JSON response

        # Assuming the response contains an array of group objects
        session['groups'] = groups_info.get('value', [])

    except Exception as e:
        # If the group request fails, print out why
        print("\nFailed to fetch groups:")
        print(e)

    return redirect('/')  # Redirect to the homepage

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('groups', None)
    return redirect('/')

# Run the Flask application
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
