"""
    Modified example - Network Access Control for SEED Emulator nodes.
"""
from py_abac import PDP, Policy, AccessRequest
from py_abac.storage.memory import MemoryStorage

# Policy definition in JSON - MODIFIED for network simulation
policy_json = {
    "uid": "1",
    "description": "AS100 and AS200 hosts are allowed to create, delete, get "
                   "any resources only if the client IP matches.",
    "effect": "allow",
    "rules": {
        "subject": [{"$.name": {"condition": "Equals", "value": "AS100"}},
                    {"$.name": {"condition": "Equals", "value": "AS200"}}],
        "resource": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "action": [{"$.method": {"condition": "Equals", "value": "create"}},
                   {"$.method": {"condition": "Equals", "value": "delete"}},
                   {"$.method": {"condition": "Equals", "value": "get"}}],
        "context": {"$.ip": {"condition": "CIDR", "value": "10.100.0.0/24"}}
    },
    "targets": {},
    "priority": 0
}

# Parse JSON and create policy object
policy = Policy.from_json(policy_json)
# Setup policy storage
storage = MemoryStorage()
# Add policy to storage
storage.add(policy)
# Create policy decision point
pdp = PDP(storage)

# Access request - AS100 host trying to get a resource
request_json = {
    "subject": {
        "id": "",
        "attributes": {"name": "AS100"}
    },
    "resource": {
        "id": "",
        "attributes": {"name": "myrn:example.com:resource:123"}
    },
    "action": {
        "id": "",
        "attributes": {"method": "get"}
    },
    "context": {
        "ip": "10.100.0.71"
    }
}

# Parse JSON and create access request object
request = AccessRequest.from_json(request_json)

if __name__ == '__main__':
    result = pdp.is_allowed(request)
    print(f"AS100 host access request: {'ALLOWED' if result else 'DENIED'}")
