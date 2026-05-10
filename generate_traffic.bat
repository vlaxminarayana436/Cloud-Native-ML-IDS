# Windows (Save as generate_traffic.bat)
@echo off
:loop
echo Sending Malicious Packet...
curl -X POST "http://localhost:8000/api/v1/packets/process" -H "Content-Type: application/json" -d "{ \"timestamp\": 1700000000.0, \"src_ip\": \"10.10.10.10\", \"dst_ip\": \"192.168.1.50\", \"protocol\": \"TCP\", \"length\": 45, \"src_port\": 60000, \"dst_port\": 2323 }"
timeout /t 2 >nul
goto loop