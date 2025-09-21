# slack.py


import json
import secrets
import base64
import asyncio
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# Replace with your HubSpot app credentials for testing
CLIENT_ID = 'YOUR_HUBSPOT_CLIENT_ID'
CLIENT_SECRET = 'YOUR_HUBSPOT_CLIENT_SECRET'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
AUTH_URL = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=contacts%20oauth&response_type=code'
TOKEN_URL = 'https://api.hubapi.com/oauth/v1/token'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)
    return f'{AUTH_URL}&state={encoded_state}'

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                TOKEN_URL,
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code,
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}')
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return credentials

def create_integration_item_metadata_object(response_json):
    # Example: create IntegrationItem for a HubSpot contact
    return IntegrationItem(
        id=response_json.get('id'),
        type='Contact',
        name=response_json.get('properties', {}).get('firstname', '') + ' ' + response_json.get('properties', {}).get('lastname', ''),
        parent_id=None,
        parent_path_or_name=None,
        creation_time=None,
        last_modified_time=None,
        url=None,
        children=None,
        mime_type=None,
        delta=None,
        drive_id=None,
        visibility=True,
    )

import requests

async def get_items_hubspot(credentials):
    # Fetch contacts from HubSpot as an example
    if isinstance(credentials, str):
        credentials = json.loads(credentials)
    access_token = credentials.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }
    url = 'https://api.hubapi.com/crm/v3/objects/contacts?limit=10'
    response = requests.get(url, headers=headers)
    items = []
    if response.status_code == 200:
        results = response.json().get('results', [])
        for contact in results:
            items.append(create_integration_item_metadata_object(contact))
    print(f'HubSpot items: {items}')
    # Return as list of dicts for JSON serialization
    return [item.__dict__ for item in items]