from flask import (
    Flask,
    redirect,
    request,
    url_for,
    session,
    render_template,
    flash,
    Response,
    jsonify,
)
from flask_session import Session
from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
import requests
import json
from models import init_app, db, DataSource, UserDataSourcePermission, User
from forms import DataSourceForm
from azure_active_directory import (
    create_aad_group,
    add_users_to_aad_group,
    create_team_from_group,
)
from cluster_manager import launch_vscode_for_user, sanitize_username
from requests.exceptions import RequestException
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from geventwebsocket import WebSocketError
import websocket
import functools

print = functools.partial(print, flush=True) # redefine to flush the buffer always

# Load secrets from a JSON file
with open("secrets.json") as f:
    secrets = json.load(f)


# Initialize the Flask application
app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*")

app.config["SECRET_KEY"] = secrets["session_secret"]
app.config["SESSION_TYPE"] = "filesystem"
app.config["LOGGING_LEVEL"] = 10

# Initialize database
init_app(app)

# Initialize the session extension
Session(app)


# Azure AD OAuth configuration
oauth = OAuth(app)
azure = oauth.register(
    "azure",
    client_id=secrets["client_id"],
    client_secret=secrets["client_s ecret"],
    server_metadata_url=f'https://login.microsoftonline.com/{secrets["tenant_id"]}/v2.0/.well-known/openid-configuration',
    client_kwargs={
        "scope": "openid email profile Group.ReadWrite.All offline_access",
        'token_endpoint_auth_method': 'none'

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

            team_creation_response = create_team_from_group(
                group_id=aad_group_id,
                access_token=session.get("token").get("access_token"),
            )
            if team_creation_response:
                print(f"Team Creation Response: %s", team_creation_response)
                team_info = team_creation_response.json()
                print(f"Team Info: %s", team_info)
                team_id = team_info.get("id")
                team_web_url = team_info.get("webUrl")
                if team_id and team_web_url:
                    data_source.team_id = team_id
                    data_source.team_web_url = team_web_url

                    db.session.commit()
                    flash(
                        "Team created and associated with data source successfully!",
                        "success",
                    )
                else:
                    flash("Failed to extract team ID or web url from the response.", "error")
            else:  # If there was an error
                flash("Failed to create the team.", "error")
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
    permissions = UserDataSourcePermission.query.filter_by(
        data_source_id=data_source.id
    ).all()
    assigned_users = [permission.user for permission in permissions]

    # Check if the current user is the admin of the data source
    current_user_id = session.get("user")["id"]
    is_admin = current_user_id == data_source.created_by  # local check

    # Now, we want to check if the current user is an admin in the AAD group
    aad_group_id = (
        data_source.aad_group_id
    )  # The ID of the AAD group associated with the data source

    # Prepare the access token for Microsoft Graph API
    access_token = session.get(
        "access_token"
    )  # The token stored in session after login

    # URL for the Microsoft Graph API endpoint to get the group's owners
    url = f"https://graph.microsoft.com/v1.0/groups/{aad_group_id}/owners"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        # Make the request to get the group's owners
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        # If the request was successful, get the JSON response
        owners_info = response.json()

        # Check if the user is an owner of the group
        is_user_aad_group_admin = any(
            owner.get("id") == current_user_id for owner in owners_info.get("value", [])
        )

    except requests.exceptions.HTTPError as err:
        print(f"An HTTP error occurred: {err}")
        return jsonify(error=str(err)), 500  # You can handle the error differently
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify(error=str(e)), 500  # You can handle the error differently

    # Check if the current user has access to the data source
    user_has_access = (
        any(user.id == current_user_id for user in assigned_users)
        or is_user_aad_group_admin
    )

    # Render the template with the necessary information
    return render_template(
        "data_source_details.html",
        data_source=data_source,
        creator=creator,
        assigned_users=assigned_users,
        user=creator,
        is_admin=is_user_aad_group_admin,
        user_has_access=user_has_access,
        team_id=data_source.team_id,
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


@app.route("/datasource/<int:id>/start_vscode", methods=["GET", "POST"])
def start_vscode(id):
    # Check if the user is logged in and has access to the data source
    if "user" not in session:
        flash("You must be logged in to access this feature.", "error")
        return redirect(url_for("login"))

    user_info = session.get("user")
    user_id = user_info.get("id")  # Or however you've structured your session/user info

    # Fetch the data source from the database
    data_source = DataSource.query.get_or_404(id)

    # Check if the user has access to the data source
    current_user_id = session.get("user")["id"]
    is_admin = current_user_id == data_source.created_by

    permissions = UserDataSourcePermission.query.filter_by(
        data_source_id=data_source.id
    ).all()
    assigned_users = [permission.user for permission in permissions]

    if user_id not in [user.id for user in assigned_users] and not is_admin:
        flash("You do not have access to this data source.", "error")
        return redirect(url_for("homepage"))  # or wherever you'd like to redirect

    sanitized_user_id = sanitize_username(user_id)

    # Start the VS Code server for the user
    try:
        vscode_url = launch_vscode_for_user(sanitized_user_id)
        flash("Your VS Code server is being started. Please wait a moment.", "success")
    except Exception as e:
        print(
            f"An error occurred while starting your VS Code server: {str(e)}", "error"
        )
        return redirect(
            url_for("data_source_details", id=id)
        )  # Redirect back to the data source details in case of failure

    # Redirect to a waiting page or directly embed the VS Code interface if it's ready
    # The implementation of this part can vary based on how you handle the VS Code UI embedding
    # return render_template("vscode.html")
    vscode_url = url_for("vscode_proxy")
    return redirect(vscode_url)


@app.route("/vscode_proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def vscode_proxy():
    """
    This route acts as a proxy for the VS Code server, forwarding requests and responses.
    """

    app.logger.info("VSCode Proxy called.")

    user_info = session.get("user")
    if not user_info:
        app.logger.warning("User is not logged in")
        return "User is not logged in", 403  # or redirect to login page

    # Retrieve the service name for the user's VS Code server based on the user's ID.
    service_name = sanitize_username(
        user_info["id"]
    )  # Assuming 'id' is the correct key
    app.logger.info(f"Service name: {service_name}")

    # Construct the URL of the VS Code server for this user.
    vscode_url = f"http://vscode-service-dbe0354c6b5f4bdc8a356af8d4ec68ed.dataaccessmanager.svc.cluster.local/"
    app.logger.info(f"VSCode URL: {vscode_url}")

    # Check if it's a WebSocket request
    if request.environ.get("wsgi.websocket"):
        app.logger.info("WebSocket request detected")
        ws_frontend = request.environ["wsgi.websocket"]
        ws_backend = create_backend_websocket(vscode_url)

        if not ws_backend:
            app.logger.error("Failed to connect to VS Code server via WebSocket")
            return "Failed to connect to VS Code server", 502

        try:
            while not ws_frontend.closed and not ws_backend.closed:
                # Forward message from frontend to backend
                message = ws_frontend.receive()
                if message is not None:
                    ws_backend.send(message)
                else:
                    break

                # Forward message from backend to frontend
                message = (
                    ws_backend.recv()
                )  # Using recv() method from 'websocket-client' library
                if message is not None:
                    ws_frontend.send(message)
                else:
                    break

        except WebSocketError as e:
            app.logger.error(f"WebSocket communication failed: {e}")
            return "WebSocket communication failed", 500

        finally:
            ws_backend.close()  # Ensure the backend WebSocket is closed

        return "", 204  # No Content response for WebSocket route

    else:
        app.logger.info("HTTP request detected")
        # For non-WebSocket requests, forward the request as is and return the response
        headers = {key: value for (key, value) in request.headers if key != "Host"}
        try:
            response = requests.request(
                method=request.method,
                url=vscode_url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
            )

            # Forward the response back to the client
            headers = [(name, value) for (name, value) in response.raw.headers.items()]
            proxy_response = Response(response.content, response.status_code, headers)
            return proxy_response

        except RequestException as e:
            app.logger.error(f"Request failed: {e}")
            return "Proxy request failed", 502  # Bad Gateway error


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


# Helper function to create a WebSocket client connected to the backend.
def create_backend_websocket(vscode_url):
    """
    Create and return a WebSocket client connected to the VS Code server.
    """
    try:
        ws = websocket.create_connection(vscode_url)
        return ws
    except Exception as e:
        app.logger.error(f"WebSocket creation failed: {e}")
        return None


# # Run the Flask application
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    # Use gevent WebSocket server to run the app instead of the standard Flask server
    http_server = WSGIServer(("127.0.0.1", 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
