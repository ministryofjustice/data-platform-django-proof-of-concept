from flask import Flask, redirect, request, url_for, session, render_template, flash
from flask_session import Session
from authlib.integrations.flask_client import OAuth
import os
import requests
import json
from models import init_app, db, DataSource, UserDataSourcePermission, User
from forms import DataSourceForm
from azure_active_directory import create_aad_group, add_users_to_aad_group


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
    user_role = session.get("user_role", "user")
    if user_info:
        try:
            # Fetch the latest group memberships from Azure AD
            groups_resp = azure.get(
                "https://graph.microsoft.com/v1.0/me/memberOf",
                token=session.get("token"),
            )
            groups_info = groups_resp.json()
            session["groups"] = groups_info.get("value", [])
        except Exception as e:
            # Handle exceptions from the API call
            print(f"Failed to refresh group memberships: {e}")
        # User is logged in, render the dashboard
        return render_template(
            "dashboard.html",
            user_info=user_info,
            groups=session.get("groups", []),
            user_role=user_role,
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
    print("\nDebugging Info: Contents of data_sources:")
    for ds in data_sources:
        print(vars(ds))
    print("\n")
    # Create a list of dictionaries containing the data you want to display
    data_sources_info = []
    for data_source in data_sources:
        info = {
            "id": data_source.id,
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


@app.route("/datasource/<int:id>")
def data_source_details(id):
    # Fetch the data source from the database
    data_source = DataSource.query.get_or_404(id)

    # Fetch the creator of the data source
    creator = User.query.get(data_source.created_by)

    # Fetch the users assigned to this data source through permissions
    # This assumes that your UserDataSourcePermission model links back to the User model
    permissions = UserDataSourcePermission.query.filter_by(
        data_source_id=data_source.id
    ).all()
    assigned_users = [permission.user for permission in permissions]

    # Check if the current user is the admin of the data source
    current_user_id = session.get("user")["id"]
    is_admin = current_user_id == data_source.created_by
    # Render the template with the necessary information
    return render_template(
        "data_source_details.html",
        data_source=data_source,
        creator=creator,
        assigned_users=assigned_users,
        user=creator,
        is_admin=is_admin,
    )


@app.route("/datasource/<int:id>/manage_users", methods=["GET", "POST"])
def manage_users(id):
    data_source = DataSource.query.get_or_404(id)

    current_user_id = session.get("user")["id"]
    current_user = User.query.get(current_user_id)

    if not current_user:  # Adjust as necessary for your permissions model
        flash("You do not have permission to manage this data source.", "error")
        return redirect(url_for("homepage"))  # or wherever you'd like to redirect

    if request.method == "POST":
        user_ids = request.form.getlist("users")

        # Assign users to the data source with appropriate permissions
        for user_id in user_ids:
            # Prevent adding the admin as a member again
            if user_id == data_source.created_by:
                continue  # Skip the admin user

            # Check if the user already has access
            existing_permission = UserDataSourcePermission.query.filter_by(
                user_id=user_id, data_source_id=data_source.id
            ).first()
            if existing_permission:
                continue
            user = User.query.get(user_id)
            if user:
                permission = UserDataSourcePermission(
                    user_id=user.id,
                    data_source_id=data_source.id,
                    permission_type="read",
                )
                db.session.add(permission)

        db.session.commit()

        # After assigning users to the data source, add them to the corresponding AAD group
        aad_group_id = (
            data_source.aad_group_id
        )  # The ID of the AAD group associated with the data source
        if aad_group_id:
            successful_additions, failed_additions = add_users_to_aad_group(
                user_ids, aad_group_id, session.get("access_token")
            )

            if failed_additions:
                flash(
                    f"Failed to add users {', '.join(failed_additions)} to the AAD group.",
                    "error",
                )
            if successful_additions:
                flash(
                    f"Successfully added users {', '.join(successful_additions)} to the AAD group.",
                    "success",
                )
        else:
            flash("No associated AAD group found for this data source.", "error")

        flash("Users successfully assigned!", "success")
        return redirect(url_for("data_source_details", id=id))  # or appropriate route

    else:
        all_users = User.query.all()

        # Get the IDs of users who already have permissions for this data source
        existing_permissions = UserDataSourcePermission.query.filter_by(
            data_source_id=data_source.id
        ).all()
        users_with_permissions = {perm.user_id for perm in existing_permissions}

        # Exclude the admin and users with existing permissions from the list
        selectable_users = [
            user
            for user in all_users
            if user.id != data_source.created_by
            and user.id not in users_with_permissions
        ]

        return render_template(
            "manage_users.html", data_source=data_source, users=selectable_users
        )


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
