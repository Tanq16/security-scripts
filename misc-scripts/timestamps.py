# Timestamp Utility
# -----------------
# This script takes in a subcommand of diff or print. For
# diff, it takes in 2 epochs and prints the difference
# between the two. For print, it takes in an ISO8601 time
# and prints the local TZ and UTC cersion of the ISO8601
# format, and also prints the human readable time in local
# TZ along with the epoch (timestamp).

import sys
import datetime

def diff_command(start_epoch, end_epoch):
    start_time = datetime.datetime.fromtimestamp(start_epoch)
    end_time = datetime.datetime.fromtimestamp(end_epoch)
    if end_epoch >= start_epoch:
        time_difference = end_time - start_time
        print(f"Time difference: {time_difference}")
    else:
        time_difference = start_time - end_time
        print(f"Time difference: -{time_difference}")

def print_command(input_time):
    iso8601_time = input_time.astimezone().isoformat()
    print(f"ISO8601:\t {iso8601_time}")
    
    utc_time = input_time.astimezone(datetime.timezone.utc)
    iso8601_utc = utc_time.isoformat()
    print(f"ISO8601 (UTC):\t {iso8601_utc}")
    
    epoch_time = int(utc_time.timestamp())
    print(f"Epoch (UTC):\t {epoch_time}")

    human_time = input_time.astimezone().strftime("%b %d, %Y %I:%M:%S %p %Z")
    print(f"Human Time:\t {human_time}")

def main(subcommand):
    if subcommand == "diff":
        start_epoch = int(sys.argv[2])
        end_epoch = int(sys.argv[3])
        diff_command(start_epoch, end_epoch)
    elif subcommand == "print":
        if sys.argv[2] == "now":
            print_command(datetime.datetime.now())
        else:
            input_time = datetime.datetime.fromisoformat(sys.argv[2])
            print_command(input_time)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: \npython3 timestamps.py diff <epoch1> <epoch2>\npython3 timestamps.py print <epoch|now>')
        sys.exit(1)
    subcommand = sys.argv[1]
    main(subcommand)
