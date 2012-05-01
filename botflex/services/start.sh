#!/bin/bash

echo "Starting"
crontab -l > tmpcron
echo "1 * * * * ~/home/sheharbano/Desktop/bash/hello_world.sh" >> tmpcron
crontab tmpcron
rm tmpcron
echo "Start done"
