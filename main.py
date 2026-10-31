import argparse
import logging
import os
import sys
import time
from pathlib import Path
import csv
try:
    import inotify.adapters
    import inotify.constants
except ImportError:
    logging.error("Missing required library: inotify. Install it with: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Generates a timeline of file modifications, accesses, and metadata changes.")
    parser.add_argument("target_directory", type=str, help="The directory to monitor.")
    parser.add_argument("-o", "--output_file", type=str, default="file_timeline.csv", help="The output CSV file (default: file_timeline.csv).")
    parser.add_argument("-r", "--recursive", action="store_true", help="Monitor the target directory recursively.")
    parser.add_argument("-e", "--events", type=str, default="modify,access,attrib,close_write,create,delete,move",
                        help="Comma-separated list of events to monitor (default: modify,access,attrib,close_write,create,delete,move).  See inotify.constants for valid events.")
    parser.add_argument("-l", "--log_level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level (default: INFO)")

    return parser

def validate_directory(directory_path):
    """
    Validates that the target directory exists and is a directory.

    Args:
        directory_path (str): The path to the directory to validate.

    Returns:
        Path: A Path object representing the validated directory.

    Raises:
        FileNotFoundError: If the directory does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    directory = Path(directory_path)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory_path}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory_path}")
    return directory

def parse_events(events_string):
    """
    Parses a comma-separated string of events into a list of inotify constants.

    Args:
        events_string (str): A comma-separated string of inotify events.

    Returns:
        list: A list of inotify event constants.

    Raises:
        ValueError: If an invalid event name is provided.
    """
    event_names = [e.strip().upper() for e in events_string.split(",")]
    event_constants = []
    for event_name in event_names:
        try:
            event_constant = getattr(inotify.constants, "IN_" + event_name)
            event_constants.append(event_constant)
        except AttributeError:
            raise ValueError(f"Invalid event name: {event_name}.  See inotify.constants for valid events.")
    return event_constants


def monitor_directory(target_directory, output_file, recursive, event_mask):
    """
    Monitors the target directory for filesystem events and writes them to a CSV file.

    Args:
        target_directory (Path): The directory to monitor.
        output_file (str): The path to the output CSV file.
        recursive (bool): Whether to monitor the directory recursively.
        event_mask (int): The inotify event mask.
    """

    row_count = 0
    try:
        i = inotify.adapters.Inotify()

        watch_flags = event_mask

        watched = []
        if recursive:
            # inotify has no recursive flag: walk the tree and add one
            # watch per directory.
            for root, dirs, files in os.walk(target_directory):
                i.add_watch(root, watch_flags)
                watched.append(root)
        else:
            i.add_watch(target_directory, watch_flags)
            watched.append(target_directory)

        logging.info(f"Monitoring directory: {target_directory}")
        logging.info(f"Outputting to: {output_file}")
        logging.info(f"Recursive: {recursive}")

        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Timestamp", "Event", "Path", "Filename"])  # Write header

            # Seed the timeline with the files already present, one row
            # per file in the watched scope, using each file's
            # modification time. The Event column carries the plain
            # marker "existing" for these rows.
            if recursive:
                seed_paths = []
                for root, dirs, files in os.walk(target_directory):
                    for fname in files:
                        seed_paths.append(Path(root) / fname)
            else:
                seed_paths = [p for p in Path(target_directory).iterdir() if p.is_file()]
            for seed in seed_paths:
                try:
                    mtime = seed.stat().st_mtime
                except OSError:
                    continue
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
                csv_writer.writerow([ts, "existing", str(seed.parent), seed.name])
                row_count += 1
            csvfile.flush()

            try:
                for event in i.event_gen(yield_nones=False):
                    (ok, watch_mask, cookie, name) = event

                    if not ok:
                        logging.error("Inotify error occurred")
                        break  # Exit the loop if there's an error.

                    event_names = [mask_name for mask_name in dir(inotify.constants)
                                   if mask_name.startswith('IN_') and getattr(inotify.constants, mask_name) & watch_mask]

                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    event_string = ", ".join(event_names)
                    file_path = Path(target_directory) / name if name else Path(target_directory)

                    csv_writer.writerow([timestamp, event_string, str(file_path.parent), name])
                    row_count += 1
                    csvfile.flush()  # Ensure data is written to disk immediately

                    logging.debug(f"Event: Timestamp={timestamp}, Event(s)={event_string}, Path={file_path.parent}, Filename={name}")

            except KeyboardInterrupt:
                logging.info("Monitoring stopped by user.")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            finally:
                i.remove_watch(target_directory)
                logging.info(f"Stopped monitoring {target_directory}")

        if row_count == 0:
            logging.error("No events recorded.")
            sys.exit(1)
        logging.info(f"Recorded {row_count} row(s) in {output_file}")

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"Failed to start monitoring: {e}", exc_info=True)
        sys.exit(1)


def main():
    """
    Main function to parse arguments, validate inputs, and start monitoring.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    try:
        # Validate inputs
        target_directory = validate_directory(args.target_directory)
        output_file = args.output_file

        # Parse events
        try:
            event_constants = parse_events(args.events)
            event_mask = sum(event_constants)
        except ValueError as e:
            logging.error(e)
            sys.exit(1)

        # Monitor directory
        monitor_directory(target_directory, output_file, args.recursive, event_mask)

    except FileNotFoundError as e:
        logging.error(e)
        sys.exit(1)
    except NotADirectoryError as e:
        logging.error(e)
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

# Usage Examples:

# 1. Monitor a directory and output to a CSV file:
# python file_timeline_generator.py /path/to/monitor -o timeline.csv

# 2. Monitor a directory recursively:
# python file_timeline_generator.py /path/to/monitor -r -o timeline.csv

# 3. Monitor only specific events (e.g., modify and create):
# python file_timeline_generator.py /path/to/monitor -e "modify,create" -o timeline.csv

# 4. Set the logging level to DEBUG:
# python file_timeline_generator.py /path/to/monitor -l DEBUG -o timeline.csv

# Offensive Tools Notes:

# This tool can be used to monitor file access and modification patterns, which can be useful in offensive security scenarios for:

# - Detecting when an attacker accesses or modifies specific files.
# - Identifying potential data exfiltration attempts based on file access patterns.
# - Tracking the activity of malware that creates, modifies, or deletes files.
# - Observing changes to configuration files or other sensitive data.

# Security best practices:
# - The tool should be run with appropriate permissions to access the target directory.
# - The output file should be stored in a secure location with restricted access.
# - Consider implementing rate limiting or filtering to prevent excessive logging and potential denial-of-service issues.
# - Regularly review the logs to identify suspicious activity.