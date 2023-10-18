import requests
from flask import session, flash

def create_aad_group(group_name, description, user_id, access_token, dry_run=False):
    # Microsoft Graph API endpoint to create a new group
    url = "https://graph.microsoft.com/v1.0/groups"

    # The headers for the request
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # The payload for the request
    group_data = {
        "displayName": group_name,
        "description": description,
        "mailEnabled": False,
        "mailNickname": group_name.replace(" ", "").lower(),
        "securityEnabled": True
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
        group_id = group_info.get('id')

        # Now, add the user as an admin of the group
        if group_id and user_id:
            add_admin_status = add_user_as_group_admin(group_id, user_id, access_token)
            if add_admin_status:
                flash('User added as an admin to the group successfully!', 'success')
            else:
                flash('Failed to add the user as an admin to the group.', 'error')
        else:
            flash('Group was created but user could not be added as an admin.', 'warning')

        return group_id

    except requests.exceptions.HTTPError as err:
        # Handle errors (print them to console or log file, display message to user, etc.)
        print(f"An HTTP error occurred: {err}")
        flash('An error occurred while creating the group.', 'error')
    except Exception as e:
        # Handle any other exceptions
        print(f"An unexpected error occurred: {e}")
        flash('An unexpected error occurred while creating the group.', 'error')

    return None

def add_user_as_group_admin(group_id, user_id, access_token):
    # Microsoft Graph API endpoint to add a member to the group
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"

    # The headers for the request
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
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
    except Exception as e:
        # Handle any other exceptions
        print(f"An unexpected error occurred: {e}")

    return False
