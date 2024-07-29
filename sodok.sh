#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <ip/network>"
  exit 1
fi

# Assign the argument to a variable
TARGET=$1

# Execute the Python script with the provided parameters
./sincan2.py "$TARGET" --port 22 -t 1.5
