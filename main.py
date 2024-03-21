import requests
import os

if __name__ == '__main__':

    # Fetch the token from environment variable
    token = os.getenv('TOKEN')
    base_url = 'https://tomjfrog.jfrog.io'

    # Check if the token is available
    if token is None:
        print("Token not found in environment variables.")
        exit()

    # See docs for this endpoint: https://jfrog.com/help/r/xray-rest-apis/violations
    url = f"{base_url}/xray/api/v1/violations"

    # Define headers and payload
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        # Filter body options might also be used creatively: created_from, created_until, etc...
        "filters": {
            "cve_id": "CVE-2022-29599"
        },
        "pagination": {
            "order_by": "created",
            "direction": "desc",
            "limit": 25,
            "offset": 1
        }
    }

    # Send POST request
    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()

        # Check if "violations" key exists in the response
        if "violations" in data:
            violations = data["violations"]

            # Iterate over each violation
            for violation in violations:
                created = violation["created"]
                watch_name = violation["watch_name"]
                issue_id = violation["issue_id"]
                infected_components_count = len(violation.get("infected_components", []))
                # Iterate over this list
                infected_components = violation["infected_components"]
                impacted_artifacts_count = len(violation.get("impacted_artifacts", []))
                impacted_artifacts = violation["impacted_artifacts"]


                # Print or process the extracted information
                print("---------------------------------------")
                print(f"Issue ID: {issue_id}")
                print(f"Created: {created}")
                print(f"Watch: {watch_name}")
                print(f"Infected Components Count: {infected_components_count}")
                print(f"Infected Components: {infected_components}")
                print(f"Impacted Artifacts Count: {impacted_artifacts_count}")
                print("Impacted:", impacted_artifacts)
                print("---------------------------------------")
        else:
            print("No violations found")
    else:
        print("Failed to retrieve data from the API")