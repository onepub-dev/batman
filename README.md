# Bataman is System Integrity Monitor

Batman includes:
* a file integrity scanner designed to meet the base requirements of PCI DSS section 11.5.
* a configurable log scanner

## File integrity scanner
Batman uses implements a two pass file integrity scanner.

You start by creating a baseline:

```bash
batman baseline
```

The baseline process scans the set of directories defined in the rules.yaml file and
creates a hash of each file.

To check that your system hasn't been altered you then run a scan:

```bash
batman scan
```

The scan checks the same set of files comparing their current hash with the
hash taken during the baseline.

Each time you alter the files on your system you need to re-run the baseline.

The scan should be scheduled with the likes of cron to at least run weekly and daily is recommended.

When used in a docker container you can use batman's built in scheduler:

batman cron "30 22 * * *".

A the cron command also allows you to recreate the baseline each time you start
your container.

batman --baseline cron "30 22 * * *"

# Log Scanning
Batman allows you to define as set of rules for scan log files for common problems.

To scan your log files you define a set of rules in rules.yaml.



# build
Build batman as follows:

```bash
sudo apt get install dart
dart pub global activate dcli
git pull https://github.com/noojee/batman.git
cd batman
dcli compile bin/batman.dart
```

The compiled exe 'batman' will be located at batman/bin/batman

You can now copy the batman exe to any binary compatible system.

batman was designed and tested on linux but will probably work on Windows and MacOS.


# Installation

Copy the batman exe generated via the build process onto the target system.

We suggest that you place it under the /opt directory.

Once you have copied the exe run:

```bash
./batman install
```

# Configuration
You can configure the set of directories that are scanned by editing the
default rules.yaml file.

The rules.yaml file is located at:

```~/.batman/rules.yaml```

## Default rules.yaml

The default rules.yaml contains:

```dart
sendEmailOnFail: false
sendEmailOnSuccess: false

# emailServerFQDN: localhost
emailServerPort: 25
# emailFromAddress: scanner@mydomain.com
# emailFailToAddress: failed.scan@mydomain.com
# emailSuccessToAddress: successful.scan@mydomain.com

# List of file system entities (directories and/or files) that are to be included in the baseline
# By default we scan the entire system excluding files/directories that are known to change.
entities:
  / 

# List of file system entities (files or directories) that are to be excluded from the baseline.
# These entities must be children of one of the directories
# listed in the entities section.
exclusions:
  - /dev
  - /sys
  - /proc
  - /tmp
  - /run
  - /home
  - /mnt/stateful_partition/home
  - /mnt/stateful_partition/var/lib/cni
  - /mnt/stateful_partition/var/lib/docker/containers
  - /mnt/stateful_partition/var/lib/docker/image
  - /mnt/stateful_partition/var/lib/docker/overlay2
  - /mnt/stateful_partition/var/lib/docker/network
  - /mnt/stateful_partition/var/lib/docker/volumes
  - /mnt/stateful_partition/var/lib/dockershim
  - /mnt/stateful_partition/var/lib/kubelet/pods
  - /mnt/stateful_partition/var/lib/metrics
  - /mnt/stateful_partition/var/lib/update_engine/prefs
  - /mnt/stateful_partition/var/log
  - /mnt/stateful_partition/var_overlay
  - /var/lib/cni
  - /var/lib/docker/containers
  - /var/lib/docker/image
  - /var/lib/docker/network
  - /var/lib/docker/overlay2
  - /var/lib/docker/volumes
  - /var/lib/dockershim
  - /var/lib/kubelet/plugins
  - /var/lib/kubelet/pods
  - /var/lib/metrics
  - /var/lib/update_engine/prefs
  - /var/log
  - /log/journal

```

The `entities` section contains a list of directories that are to be monitored.

The `exclusions` section is a list of files and subdirectories that are contained
in the `entities` section that should be excluded.

This allows you to exclude specific subdirectories which don't need to be scanned.

# Email notifications
You can configure batman to email the results of scans.

In the rules.yaml located at:

```~/.batman/rules.yaml```

You can add the following settings.

| Field | domain | default | description |
| ----- | ------ | ------- | ----------- |
| sendEmailOnFail| true or false | false | If true then an email is sent after every failed scan |
| sendEmailOnSuccess| true or false | false |  If true then an email is sent after every succesful scan|
| emailServerFQDN| fqdn | localhost | The fully qualified domain name of the smtp server |
| emailServerPort| integer | 25 | The port no. of the smtp server |
| emailFromAddress| email address| none | The email address to use as the 'from' address when sending emails
| emailFailToAddress| email address | none | The email address send failed scans to
| emailSuccessToAddress| email address | emailFailToAddress | The email address to send succesful scans to. If not set then we use the emailFailToAddress address.


# Scheduling scans

You should schedule scans on at least a weekly basis and preferably daily.

To create a schedule use cron

Edit /etc/conron.d/crontab.daily

To run the scan every day at 10:30 pm add the following line:

30   22  *   *   *  someuser  /opt/batman scan > /var/log/batman.log


## Batman cron
batman also includes a built in cron process. 

This is primarily designed for docker containers that only allow a single 
executable to run.

There is an example Dockerfile in the examples directory.

To build and run the Dockerfile

```bash
docker build -t batman .
docker run batman
```







