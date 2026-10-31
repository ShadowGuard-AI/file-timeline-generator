![Banner](banner.png)

# file-timeline-generator
Generates a timeline of file modifications, accesses, and metadata changes based on filesystem events (inotify or similar). Outputs a CSV for analysis. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowGuardAI/file-timeline-generator`
Then install the dependencies: `pip install -r requirements.txt`
The tool needs the inotify package from requirements.txt. Without it, any run prints a line naming the missing library and the install command, and exits 1.

## Usage
`./file-timeline-generator [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: The output CSV file (default: file_timeline.csv)
- `-r`: Monitor the target directory recursively (one watch per directory in the tree).
- `-e`: Comma separated list of events to monitor.
- `-l`: Set the logging level.

## Output
At startup the CSV is seeded with one row per file already present in the watched scope (all subdirectories when `-r` is given). A seeded row uses the file modification time as its timestamp and carries the plain marker `existing` in the Event column. Live events are appended after the seeded rows, with the inotify constant name (for example IN_CREATE) in the Event column. When monitoring stops, the run logs how many rows were recorded. A session that records no rows at all prints "No events recorded." and exits 1.

## License
Copyright (c) ShadowGuardAI
