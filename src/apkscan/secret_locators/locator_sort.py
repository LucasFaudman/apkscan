from json import load as json_load, dump as json_dump
from pathlib import Path

PARENT = Path(__file__).parent
all_locators_path = PARENT / "all_secret_locators.json"
with open(all_locators_path, "r") as f:
    all_locator_dicts = json_load(f)

curated_path = PARENT / "curated.json"
generic_path = PARENT / "generic.json"
cloud_path = PARENT / "cloud.json"
endpoint_path = PARENT / "endpoint.json"
backend_path = PARENT / "backend.json"
secret_path = PARENT / "secret.json"
key_locators_path = PARENT / "key_locators.json"
aws_path = PARENT / "aws.json"
azure_path = PARENT / "azure.json"
gcp_path = PARENT / "gcp.json"

def matches_terms(locator_dicts, terms):
    matching = []
    for locator_dict in locator_dicts:
        if any(term.lower() in value.lower() for term in terms for value in map(str, locator_dict.values())):
            matching.append(locator_dict)
    return matching

generic_locators = matches_terms(all_locator_dicts, ["generic"])
cloud_locators = matches_terms(all_locator_dicts, ["cloud", 'aws', 'azure', 'gcp', 'amazon', 'google', 'microsoft'])
endpoint_locators = matches_terms(all_locator_dicts, ["endpoint", "domain", 'host', 'address', 'interface', 'rest', 'http'])
key_locators = matches_terms(all_locator_dicts, ["key", "token"])
secret_locators = matches_terms(all_locator_dicts, ["secret"])
curated_locators = matches_terms(all_locator_dicts, ["rsa", "ssh", "secret", "openai", "aws", "azure", "gcp", "amazon", "google", "microsoft", "endpoint", "domain", 'host', 'address', 'interface', 'rest', 'http',])
aws_locators = matches_terms(all_locator_dicts, ["aws", "amazon"])
azure_locators = matches_terms(all_locator_dicts, ["azure", "microsoft"])
gcp_locators = matches_terms(all_locator_dicts, ["gcp", "google"])

for locator_dicts, path in zip(
    [generic_locators, cloud_locators, endpoint_locators,
     key_locators, curated_locators, secret_locators,
     aws_locators, azure_locators, gcp_locators,
     ],

     [generic_path, cloud_path, endpoint_path, key_locators_path,
      curated_path, secret_path,
      aws_path, azure_path, gcp_path,]):

    print(f"Writing {len(locator_dicts)} locators to {path}.")
    with path.open("w+") as f:
        json_dump(locator_dicts, f, indent=4)
