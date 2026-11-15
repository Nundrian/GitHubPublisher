@echo off
rem Checks that the open-webui container reaches the publisher on the host WITHOUT sending the token.
rem Expected output: 401  (reachable, authentication enforced). 000 = not reachable.
docker exec open-webui curl -s -o /dev/null -w "%%{http_code}\n" --max-time 5 http://host.docker.internal:8766/v1/status
pause
