# PCI File Integrity Scanner

pcifim is an file integrity scanner designed to meet the base requirements of PCI DSS section 11.5.

Pcifim protects the integrity of your files using a two pass strategy.

You start by creating a baseline:

```bash
pcifim baseline
```

The baseline process scan the set of directories defined in the rules.yaml file and
creates a hash of each file.

To check that your system hasn't been altered you then run a scan:

```bash
pcifim scan
```

The scan checks the same set of files comparing their current hash with the
hash taken during the baseline.

Each time you alter the files on your system you need to re-run the baseline.

The scan should be scheduled with the likes of cron to at least run weekly and daily is recommended.



# build
Build pcifim as follows:

```bash
sudo apt get install dart
dart pub global activate dcli
git pull https://github.com/noojee/pci_file_monitor.git
cd pci_file_monitor
dcli compile bin/pcifim.dart
```

The compiled exe 'pcifmi' will be located at pci_file_monitor/bin/pcifim

You can now copy the pcifim exe to any binary compatible system.

pcifim was designed and test on linux but will probably work on Windows and MacOS.


# Installation

Copy the pcifim exe generated via the build process onto the target system.

We suggest that you place it under the /opt directory.

Once you have copied the exe run:

```bash
./pcifim install
```

# Configuration
You can configure the set of directories that are scanned by editing the
default rules.yaml file.

The rules.yaml file is located at:

```~/.pcifim/rules.yaml```

## Default rules.yaml

The default rules.yaml contains:

```dart
# List of file system entities (directories and/or files) that are to be included in the baseline
entities:
  - /sbin
  - /usr/bin
  - /usr/sbin
  - /etc
  - /opt

# List of file system entities (files or directories) that are to be excluded from the baseline.
# These entities must be children of one of the directories
# listed in the entities section.
exclusions:
  - /etc/hosts

```

The `entities` section contains a list of directories that are to be monitored.

The `exclusions` section is a list of files and subdirectories that are contained
in the `entities` section that should be excluded.

This allows you to exclude specific subdirectories which don't need to be scanned.

# Email notifications
You can configure pcifim to email the results of scans.

In the rules.yaml located at:

```~/.pcifim/rules.yaml```

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

30   22  *   *   *  someuser  /opt/pcifim scan > /var/log/pcifim.log




