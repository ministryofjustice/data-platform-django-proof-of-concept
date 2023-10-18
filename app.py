from flask import Flask, redirect, url_for, session, render_template, flash
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import os
import requests
import json
from models import init_app, db, DataSource, UserDataSourcePermission, User
from forms import DataSourceForm
from azure_active_directory import create_aad_group


# Load secrets from a JSON file
with open("secrets.json") as f:
    secrets = json.load(f)


# Initialize the Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets["session_secret"]
app.config["SESSION_TYPE"] = "filesystem"

# Initialize database
init_app(app)

# Initialize the session extension
Session(app)


# Azure AD OAuth configuration
oauth = OAuth(app)
azure = oauth.register(
    "azure",
    client_id=secrets["client_id"],
    client_secret=secrets["client_secret"],
    server_metadata_url=f'https://login.microsoftonline.com/{secrets["tenant_id"]}/v2.0/.well-known/openid-configuration',
    client_kwargs={
        "scope": "openid email profile User.ReadWrite.All Group.ReadWrite.All offline_access",
    },
)


@app.route("/")
def homepage():
    user_info = session.get("user")
    groups = session.get("groups")
    user_role = session.get("user_role", "user")
    if user_info:
        # User is logged in, render the dashboard
        return render_template(
            "dashboard.html", user_info=user_info, groups=groups, user_role=user_role
        )
    # For logged-out users, render the homepage
    return render_template("homepage.html")


@app.route("/login")
def login():
    redirect_uri = url_for("authorized", _external=True)
    return azure.authorize_redirect(redirect_uri)


@app.route("/login/authorized")
def authorized():
    token = azure.authorize_access_token()
    access_token = token.get("access_token")
    if access_token:
        session["access_token"] = access_token
    user_resp = azure.get("https://graph.microsoft.com/v1.0/me", token=token)
    user_info = user_resp.json()

    # Debug: Print the whole response to see all available fields
    print("\nUser response:")
    print(json.dumps(user_info, indent=4))  # Pretty-print the JSON response

    # Extract user information from the response
    user_id = user_info.get(
        "id"
    )  # Adjust if the ID is under a different key in the response
    user_name = user_info.get("displayName")  # Or appropriate field for the user's name
    user_email = user_info.get(
        "userPrincipalName"
    )  # Or appropriate field for the user's email

    # Check if the user exists in the database
    user = User.query.get(user_id)
    if not user:
        # User not found in the database, so let's create a new one
        user = User(
            id=user_id,
            name=user_name,
            email=user_email,
            # ... any other fields you want to populate ...
        )
        db.session.add(user)
        db.session.commit()
        print(f"User {user_name} added to the database.")

    # Store user info in session
    session["user"] = user_info
    session["token"] = token

    # Attempt to get the user's group memberships
    try:
        groups_resp = azure.get(
            "https://graph.microsoft.com/v1.0/me/memberOf", token=token
        )
        groups_info = groups_resp.json()

        # Debug: Print the groups response
        print("\nGroups response:")
        print(json.dumps(groups_info, indent=4))  # Pretty-print the JSON response

        # Assuming the response contains an array of group objects
        session["groups"] = groups_info.get("value", [])

    except Exception as e:
        # If the group request fails, print out why
        print("\nFailed to fetch groups:")
        print(e)

    # Determine if the user is an admin
    is_admin = check_if_user_is_admin(session.get("groups", []))

    # Store role in session
    session["user_role"] = (
        "admin" if is_admin else "user"
    )  # It seems there was a typo here, setting 'user' for non-admins

    return redirect("/")  # Redirect to the homepage


@app.route("/datasource/create", methods=["GET", "POST"])
def create_data_source():
    form = DataSourceForm()
    # token = azure.authorize_access_token()
    if form.validate_on_submit():
        current_user_id = session["user"]["id"]
        # Create a new data source instance
        data_source = DataSource(
            name=form.name.data,
            description=form.description.data,
            aws_resource_arn=form.aws_resource_arn.data,
            created_by=current_user_id,
        )

        # Add to the database session and commit
        db.session.add(data_source)
        db.session.commit()

        group_name = f"data_platform_datasource_{form.name.data}_{data_source.id}"

        # Create the group in Azure AD
        aad_group_id = create_aad_group(
            group_name=group_name,
            description=form.name.data,
            access_token=session.get("token").get("access_token"),
            user_id=current_user_id,
            dry_run=False,
        )

        if aad_group_id:
            data_source.aad_group_id = aad_group_id  # Save the new AAD group ID
            db.session.commit()

            flash(
                "Data source and associated AAD group created successfully!", "success"
            )
        else:
            flash("Failed to create AAD group.", "error")

        flash("Data source created successfully!", "success")
        return redirect(
            url_for("list_data_sources")
        )  # Redirect to the homepage or list of data sources

    # If the form is not submitted or not valid, render the form page
    return render_template("create_data_source.html", form=form)


@app.route("/datasources")
def list_data_sources():
    # Query all data sources from the database
    data_sources = DataSource.query.all()

    # Create a list of dictionaries containing the data you want to display
    data_sources_info = []
    for data_source in data_sources:
        info = {
            "name": data_source.name,
            "description": data_source.description,
            "created_by": User.query.get(data_source.created_by).name
            if data_source.created_by
            else "N/A",  # Assuming 'created_by' is a field in your DataSource model
            "created_at": data_source.created_at.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),  # Format the date as you prefer
        }
        data_sources_info.append(info)

    # Pass the list of dictionaries to the template
    return render_template("data_sources.html", data_sources=data_sources_info)


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("groups", None)
    return redirect("/")


def check_if_user_is_admin(group_ids):
    admin_group_name = "data-platform-single-ui-group"  # This should be the actual ID of your admin group in Azure AD

    # Debugging: Print the group information to the console for verification
    print("\nDebugging Info: Groups associated with the user:")
    for group in group_ids:
        print(group.get("displayName"))

    # Extracting the 'displayName' from each group and checking if 'admin_group_name' is one of them
    is_user_admin = any(
        group.get("displayName") == admin_group_name for group in group_ids
    )

    # Debugging: Print whether the user is an admin
    print(f"Is the user an admin: {is_user_admin}")

    return is_user_admin


# Run the Flask application
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
