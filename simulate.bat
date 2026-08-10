@echo off
echo Starting attack simulation via Docker...
docker run --rm --network deciptionnet_deceptionnet -v "%cd%\simulate_attack.py:/simulate_attack.py" python:3.10-slim sh -c "pip install paramiko && sed -i 's/HOSTNAME = \"localhost\"/HOSTNAME = \"honeypot\"/g' /simulate_attack.py && python /simulate_attack.py"
echo Done!
