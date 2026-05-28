import sys
import os
import json

sys.path.insert(0, '/opt/aiwarden')

from vault.vault import TokenVault
from sanitizer.layer1 import Layer1Tokenizer
from sanitizer.layer2 import Layer2Scanner
from sanitizer.layer3 import EgressChecker
from sanitizer.layer4 import Layer4Verifier
from sanitizer import run_pipeline
from canary.canary import CanarySystem
from sfl.transformer import SFLTransformer
from api.client import ZKDPClient
from registry.registry import ServiceRegistry

if len(sys.argv) < 2:
    print("Usage: python3 diagnose.py <logfile>")
    sys.exit(1)

log_file = sys.argv[1]
if not os.path.exists(log_file):
    print(f"File not found: {log_file}")
    sys.exit(1)

with open(log_file, 'r') as f:
    log_content = f.read()

v = TokenVault()
v.new_session()
l1 = Layer1Tokenizer(v)
l2 = Layer2Scanner(v)
l3 = EgressChecker(v)
l4 = Layer4Verifier(v)
c = CanarySystem()
t = SFLTransformer()
r = ServiceRegistry()
client = ZKDPClient()

print(f"Processing {log_file}...")
sanitized = run_pipeline(log_content, v, l1, l2, l3, l4, c)
packet = t.transform(sanitized, v)
channel_b = r.get_channel_b(packet['div'][0]['token'])

print(f"Packet type: {packet['packet_type']} | Events: {len(packet['div'])} | MAG: {packet['mag']}")
print("Sending to Claude...")

response = client.send(packet, channel_b, v)
if response:
    print(json.dumps(response, indent=2))
else:
    print("No response or confidence too low")
