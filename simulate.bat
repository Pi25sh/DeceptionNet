@echo off
echo Starting attack simulation via Docker...
docker run --rm --network deciptionnet_honeypot_net -v "%cd%\simulate_attack.py:/simulate_attack.py" python:3.10-slim sh -c "pip install paramiko && sed 's/HOSTNAME = \"localhost\"/HOSTNAME = \"honeypot\"/g' /simulate_attack.py > /tmp/sim.py && python /tmp/sim.py"
echo Done!
