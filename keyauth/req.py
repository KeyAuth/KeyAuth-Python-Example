from requests import post as req_post, exceptions, get as req_get
from time import sleep, strftime
from os import makedirs, path, _exit
from discord_interactions import verify_key
import datetime

def post(data, timeout=15):
    try:
        response = req_post("https://keyauth.win/api/1.3/", data=data, timeout=timeout)

        # For log or file post types, return raw text from response server
        if data["type"] in {"log", "file"}:
            return response.text

        # Validate signature timestamp for security
        signature = response.headers["x-signature-ed25519"]
        timestamp = int(response.headers["x-signature-timestamp"])
        current_time = int(datetime.datetime.utcnow().timestamp())

        if current_time - timestamp > 20:
            print("Warning: Timestamp is older than 20 seconds.")
            sleep(3)
            _exit(1)

        # Ensure KeyAuth log directory structure exists
        keyauth_dir = "C:\\ProgramData\\KeyAuth\\Debug"
        exe_name = path.basename(__file__)
        exe_log_dir = path.join(keyauth_dir, exe_name)

        if not path.exists(exe_log_dir):
            makedirs(exe_log_dir)

        # Append log entry if response is under 200 characters
        if len(response.text) <= 200:
            log_entry = f"{strftime('%I:%M %p | %m/%d/%Y')} | {data['type']}\nResponse: {response.text}\n"
            with open(path.join(exe_log_dir, "log.txt"), "a") as log_file:
                log_file.write(log_entry)

        if not verify_key(response.text.encode('utf-8'), signature, str(timestamp), '5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b'):
            print("Signature checksum failed. Request was tampered with or session ended most likely.")
            print("Response: " + response.text)
            return response.text

        return response.text

    except exceptions.Timeout:
        print("Request timed out. The server may be temporarily unavailable.")
