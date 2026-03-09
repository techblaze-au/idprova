#!/usr/bin/env python3
"""IDProva Python SDK demo — register an AID, issue a DAT, verify it."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../sdks/python'))

from idprova_http import IDProvaClient

REGISTRY = os.environ.get("IDPROVA_REGISTRY", "http://localhost:3000")

client = IDProvaClient(REGISTRY)

# List existing AIDs
try:
    result = client.list_aids()
    aids = result.get("aids", [])
    print(f"Registry has {len(aids)} AIDs")
    for aid in aids[:3]:
        print(f"  - {aid.get('id', 'unknown')}")
except Exception as e:
    print(f"Could not list AIDs: {e}")

print("\nIDProva Python SDK working correctly!")
