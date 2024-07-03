#!/bin/bash

# Change to the Nmap scripts directory
cd /usr/share/nmap/scripts
if [ $? -ne 0 ]; then
    echo "Error: Failed to change directory to /usr/share/nmap/scripts."
    exit 1
fi

# Clone the vulscan repository
git clone https://github.com/scipag/vulscan scipag_vulscan
if [ $? -ne 0 ]; then
    echo "Error: Failed to clone the repository https://github.com/scipag/vulscan."
    exit 1
fi

# Create a symbolic link
ln -s /usr/share/nmap/scripts/scipag_vulscan /usr/share/nmap/scripts/vulscan
if [ $? -ne 0 ]; then
    echo "Error: Failed to create symbolic link for vulscan."
    exit 1
fi

# Change permissions of the update script
chmod 744 vulscan/update.sh
if [ $? -ne 0 ]; then
    echo "Error: Failed to change permissions for vulscan/update.sh."
    exit 1
fi

# Run the update script
./vulscan/update.sh
if [ $? -ne 0 ]; then
    echo "Error: Failed to execute vulscan/update.sh."
    exit 1
fi

echo "Script executed successfully."

