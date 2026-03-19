"""
    New policy file - SEED Emulator Network Security Policies.
    AS100 can access AS200. AS150 is DENIED access to AS200.
"""
from py_abac import PDP, Policy, AccessRequest
from py_abac.storage.memory import MemoryStorage

# Policy 1 - Allow AS100 to access AS200
policy1_json = {
    "uid": "1",
    "description": "AS100 is allowed to access AS200 resources",
    "effect": "allow",
    "rules": {
        "subject": [{"$.name": {"condition": "Equals", "value": "AS100"}}],
        "resource": {"$.name": {"condition": "Equals", "value": "AS200"}},
        "action": [{"$.method": {"condition": "Equals", "value": "get"}}],
        "context": {}
    },
    "targets": {},
    "priority": 0
}

# Policy 2 - Deny AS150 from accessing AS200
policy2_json = {
    "uid": "2",
    "description": "AS150 is denied access to AS200 resources",
    "effect": "deny",
    "rules": {
        "subject": [{"$.name": {"condition": "Equals", "value": "AS150"}}],
        "resource": {"$.name": {"condition": "Equals", "value": "AS200"}},
        "action": [{"$.method": {"condition": "Equals", "value": "get"}}],
        "context": {}
    },
    "targets": {},
    "priority": 1
}

# Setup storage and add both policies
storage = MemoryStorage()
storage.add(Policy.from_json(policy1_json))
storage.add(Policy.from_json(policy2_json))
pdp = PDP(storage)

# Test AS100 accessing AS200
request1 = AccessRequest.from_json({
    "subject": {"id": "1", "attributes": {"name": "AS100"}},
    "resource": {"id": "2", "attributes": {"name": "AS200"}},
    "action": {"id": "3", "attributes": {"method": "get"}},
    "context": {}
})

# Test AS150 accessing AS200
request2 = AccessRequest.from_json({
    "subject": {"id": "4", "attributes": {"name": "AS150"}},
    "resource": {"id": "2", "attributes": {"name": "AS200"}},
    "action": {"id": "3", "attributes": {"method": "get"}},
    "context": {}
})

if __name__ == '__main__':
    print("=== SEED Emulator ABAC Policy Test ===")
    print(f"AS100 -> AS200: {'ALLOWED' if pdp.is_allowed(request1) else 'DENIED'}")
    print(f"AS150 -> AS200: {'ALLOWED' if pdp.is_allowed(request2) else 'DENIED'}")
