import requests
from flask import flash
import functools
import time

print = functools.partial(print, flush=True) # redefine to flush the buffer always


def create_aad_group(group_name, description, user_id, access_token, dry_run=False):
    # Microsoft Graph API endpoint to create a new group
    url = "https://graph.microsoft.com/v1.0/groups"

    # The headers for the request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The payload for the request, setting 'visibility' to 'Private' to make a private group
    group_data = {
        "displayName": group_name,
        "description": description,
        "groupTypes": ["Unified"],
        "mailEnabled": True,
        "mailNickname": group_name.replace(" ", "").lower(),
        "securityEnabled": False,
        "visibility": "Private",  # Setting the group as a private group
    }

    # If dry_run is enabled, we skip the actual creation process
    if dry_run:
        print("Dry run enabled. No group was actually created.")
        print("Group data:", group_data)
        return "mock_group_id"

    try:
        # Make the request to create the group
        response = requests.post(url, headers=headers, json=group_data)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        # If the request was successful, get the JSON response
        group_info = response.json()

        # Extract the id of the created group
        group_id = group_info.get("id")

        # Now, add the user as an admin of the group
        if group_id and user_id:
            add_admin_status = add_user_as_group_admin(group_id, user_id, access_token)
            if add_admin_status:
                flash("User added as an admin to the group successfully!", "success")
            else:
                flash("Failed to add the user as an admin to the group.", "error")
                print("Failed to add the user as an admin to the group.", "error")
        else:
            flash(
                "Group was created but user could not be added as an admin.", "warning"
            )

        return group_id

    except requests.exceptions.HTTPError as err:
        # Handle errors (print them to console or log file, display message to user, etc.)
        print(f"An HTTP error occurred: {err}")
        flash("An error occurred while creating the group.", "error")
    except Exception as e:
        # Handle any other exceptions
        print(f"An unexpected error occurred: {e}")
        flash("An unexpected error occurred while creating the group.", "error")

    return None


def create_team_from_group(group_id, access_token):
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/team"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    team_data = {
        "memberSettings": {"allowCreateUpdateChannels": True},
        "messagingSettings": {
            "allowUserEditMessages": True,
            "allowUserDeleteMessages": True,
        },
        "funSettings": {"allowGiphy": True, "giphyContentRating": "Moderate"},
    }

    retry_count = 0
    max_retries = 5
    backoff_time = 10  # seconds

    while retry_count < max_retries:

        try:
            response = requests.put(
                url, headers=headers, json=team_data
            )  # Using PUT as per Graph API documentation for creating team from group
            response.raise_for_status()
            # If the request was successful, get the JSON response
            return response
        except requests.exceptions.HTTPError as err:
            print(f"HTTP Error {err} encountered...")
            if response.status_code == 404 and retry_count < max_retries - 1:
                print(f"404 error encountered, retrying in {backoff_time} seconds...")
                time.sleep(backoff_time)
                retry_count += 1
                continue
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            flash("An unexpected error occurred while creating the team.", "error")
            return None


def add_user_as_group_admin(group_id, user_id, access_token):
    # Microsoft Graph API endpoint to add a member to the group
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"

    # The headers for the request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The payload for the request
    member_data = {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    }

    try:
        # Make the request to add the user to the group
        response = requests.post(url, headers=headers, json=member_data)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        # If the request was successful, return True
        if response.status_code == 204:  # 204 No Content response means success
            return True
    except requests.exceptions.HTTPError as err:
        print(f"An HTTP error occurred: {err}")
    except Exception as e:
        # Handle any other exceptions
        print(f"An unexpected error occurred: {e}")

    return False


def add_user_to_aad_group(user_id, group_id, access_token):
    # Microsoft Graph API endpoint to add a member to the group
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"

    # The headers for the request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The payload for the request
    member_data = {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    }

    try:
        # Make the request to add the user to the group
        response = requests.post(url, headers=headers, json=member_data)
        response.raise_for_status()  # Will raise an HTTPError if the HTTP request returned an unsuccessful status code

        # If the request was successful, return True
        if response.status_code == 204:  # 204 No Content response means success
            return True
    except requests.exceptions.HTTPError as err:
        # Handle errors (print them to console or log file, display message to user, etc.)
        print(f"An HTTP error occurred: {err}")
        print("Response body:", err.response.text)
        flash("An error occurred while adding the user to the group.", "error")
    except Exception as e:
        # Handle any other exceptions
        print(f"An unexpected error occurred: {e}")
        flash(
            "An unexpected error occurred while adding the user to the group.", "error"
        )

    return False


def add_users_to_aad_group(user_ids, group_id, access_token):
    successful_additions = []
    failed_additions = []

    for user_id in user_ids:
        success = add_user_to_aad_group(user_id, group_id, access_token)
        if success:
            successful_additions.append(user_id)
        else:
            failed_additions.append(user_id)

    return successful_additions, failed_additions
