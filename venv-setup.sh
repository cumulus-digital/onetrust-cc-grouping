#!/usr/bin/env bash
# Set up and source a Python venv
echo "Creating python venv..."
/usr/bin/env python3 -m venv .venv
echo "Activating venv and ensuring dependencies are installed..."
source .venv/bin/activate
/usr/bin/env pip3 install python-dotenv
/usr/bin/env pip3 install requests
echo
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	echo "You may now enter the venv by running:"
	echo "source .venv/bin/activate"
else
	echo "You will now be returned to the activated venv."
	echo "Leave the venv by normal means, running 'deactivate'."
fi