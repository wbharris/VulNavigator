#!/bin/bash

# Configure dpkg
echo "Configuring dpkg..."
sudo dpkg --configure -a

# Install missing dependencies
echo "Installing missing dependencies..."
sudo apt install -f

# Update and upgrade packages
echo "Updating and upgrading packages..."
sudo apt update -y && sudo apt upgrade -y && sudo apt dist-upgrade -y

# Remove unnecessary packages
echo "Removing unnecessary packages..."
sudo apt --purge autoremove -y

# Clean package cache
echo "Cleaning package cache..."
sudo apt autoclean -y

# Handle errors
if [ $? -ne 0 ]; then
    echo "An error occurred during the update process."
    exit 1
fi

echo "Update completed successfully!"