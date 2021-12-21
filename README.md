# Batman is a System Integrity Monitor

Batman includes:
* a file integrity scanner that detects changed files and is designed to meet the base requirements of PCI DSS section 11.5.
* log scanner which looks for anomalies in your log files.

## File integrity scanner
Batman implements a two pass file integrity scanner. The two passes are

* baseline scan
* integrity scan


The baseline process scans the set of directories defined in the batman.yaml file and
creates a hash of each file.

The integrity scan re-scans the defined directories and compares the current hashes
of each file with those collected during the baseline.
Any changes to a files content is reported as well as any new or deleted files.


## Log Scanning
Batman allows you to define a set of rules for scanning log files for common problems.

To scan your log files you define a set of rules in batman.yaml.

A batman.yaml may contain multiple rules and log_sources.

## Notifications
Batman logs any detected issue and optionally emails notifications to a configuratble email address.

# File Integrity Scanner
The File Inegrity Scanner is designed to detect hacking attempts by looking for alterations to your filesystem.

To detect these changes you first create a baseline and then run daily integrity scans looking for modifications to your filesystem.

## create a baseline
To use the File Integrity Scanner you start be creating a baseline.

```bash
batman baseline
```

Each time you upgrade your system or make any changes to the file system you need to create a new baseline.

The set of directories scanned is defined by the batman.yaml file.

If you change the set of scanned directories in batman.yaml then you need to run a new baseline.

When scanning the baseline command will print each file that it scans to stdout.

The --quiet command line flag supresses the logging of each scanned file and only reports totals once the scan is complete.

The --count command line flag reports accumulated totals as the scan runs.
```bash
batman baseline --count
```

## check file integrity

To check that your system hasn't been altered since the last baseline you run an integrity scan:

```bash
batman integrity
```

The integrity scan checks the set of directories defined in batman.yaml against the baseline.
Any changes, adds or deletes are notified.

When scanning each file that it scans is printed to stdout.

The --quiet command line flag supresses the logging of each scanned file and only reports totals once the scan is complete.

The --count command line flag reports accumulated totals as the scan runs.
```bash
batman integrity --count
```

### scheduling

The integrity scan should be scheduled with the likes of cron to run at least weekly and daily is recommended.

#### cron
To create a schedule using cron:

Edit /etc/conron.d/crontab.daily

To run the scan every day at 10:30 pm add the following line:

```
0 30 22 * * *  someuser  /<path>/batman scan > /var/log/batman.log
```

#### batman cron

When used in a docker container you can use batman's built in scheduler:

```bash
batman cron "0 30 22 * * *".
```

The cron command also allows you to recreate the baseline each time you start
your container.

```bash
batman --baseline cron "0 30 22 * * *"
```

# Configuration

### batman.yaml
Batman is configured via batman.yaml file which is normally located in:
```bash
<HOME>/.batman/batman.yaml
```

See the [installation](#installation) section for details on changing the path. 

### database
Batman uses a Hive database to store the baseline which is normally located in:

```bash
<HOME>/.batman/hive
```

See the [installation](#installation) section for details on changing the path. 

## File Integrity Monitor

The file integrity monitor is configured via the batman.yaml file.

Under the file_integrity key you will find the following nested keys.

| key| domain|default|description
| --- | --- | --- | ---
|scan_byte_limit | integer | 25000000 | The maximum no. of bytes to read from a file when generating a checksum. Very large files tend not to be executable or configuration files so don't require the same level of scanning.
| entities | list of paths | none | provides a list of files and/or directories to be scanned.
| exclusions | list of paths | none | provide a list of files and/or directories that are to be excluded. These entities must always be contained within one of the paths listed in entities.

```yaml
send_email_on_fail: false
send_email_on_success: false
email_server_host: localhost
email_server_port: 25
email_from_address: scanner@mydomain.com
email_fail_to_address: failed.scan@mydomain.com
email_success_to_address: successful.scan@mydomain.com
db_path: ~/batman/hive
scan_byte_limit: 25000000

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
```

See the section on [Default batman.yaml](#default-batman-yaml)
## Log Scanner
The log scanner is configured via the batman.yaml file.

Configuration for the log scanner is built up from a number of components

* log_sources
* rules
* selectors

The following example defines one log_source and two rule.

```yaml
log_audits:
  log_sources:
    - log_source:
      description: File Integrity logs
      type: file
      top: 1000
      path: /var/log/batman.log
      rules:
        - rule: creditcard
        - rule: errors
 
  rules:
    - rule:
      name: creditcard
      description: Scans for credit cards 
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected in a log file
          risk: critical 
           

    - rule:
      name: errors
      description: Scans for general errors and warnings.
      selectors:
        - selector:
          type: contains
          description: An error was detected
          match: ['Error']
          risk: high
          continue: false
     
```      

## Configuration
## log_source
A log source lets you define how to obtain a log file to be scanned.

Each log source may define one or more of the following common attributes:
| Attribute | Domain | Required | Description
|- |-|-|-
| type | file \| journald \| docker| yes |The type of log source
| top | integer | no | Controls how may of the detected matches are notified.
| description | string | yes | A description of the log source which is used when reporting matches.
| trim_prefix | regex | no |When reporting a match the line is trimmed upto and including the trim_prefix. If there is no trim_prefix or no part of the line matches the trim_prefix then the entire line will be reported.
|reset | String | no | Used to reset the counters and discared lines selected to the point where a log line matches the reset string. This is used by log_sources that are only interested in output since the last restart of the system.
|group_by|regex | no | Cause all selected lines to be grouped by the part of the line that matches the regular expression. See the section on [reporting](#reporting) for details.




There are a number of log_sources

| Type | Description |
|------|------------ |
|File  | The log data is stored in a file |
|journalctl | The log data is read via journalctl |
|Docker | The log data is retrieved from a docker container that writes via journald|

### File
The File log source allows you to define the following unique attributes:
| Attribute | Description
|- |-
|path | The fully qualified path to the log file|

The following defines a 'file' based log source. The file is located a `/var/log/batman.log` and the first 1000 matched lines will be reported.
Each line will be trimmed up to and including the ':::' characters. 
The file will be scanned using the rules `errors` and `integrity checks`.
```yaml
log_audits:
  log_sources:
    - log_source:
      type: file
      description: File Integrity logs
      path: /var/log/batman.log
      top: 1000
      trim_prefix: ':::'
      rules: 
        - rule: integrity check
        - rule: errors
```        

### journalctl
The journald log source is able to read data from journalctl.
You specificfy the journalctl args to control which journalctl files are to be scanned.
| Attribute | Description
|- |-
|args | The arguments to be pass to journalctl.|

```yaml
log_audits:
  log_sources:
    - log_source:
      type: journald
      description: creditcards
      args: -u sshd.service --since yesterday
      top: 1000
      trim_prefix: ':::'
      rules:
        - rule: integrity check
        - rule: errors
```     

### Docker
The docker log source is able to read data from a docker log that was written to journald.

You specify the docker container name.
| Attribute | Description
|- |-
|container | The docker container name to pass to journalctl.|
|since | The duration to be passed to the journalctl --since argument.

## Rule
A rule is a resuable definition of what log entries are of interest.

You may define multiple rules and then configure log_sources to use the defined rules.
A rule may be used by multiple log sources.

A rule defines multiple selectors that control what lines are selected.

| Attribute | Domain | Description
|- |- |-
|name | String |A unique name for the rule. log_sources use the name to select a rule to use|
|description | String | A description of the rule used when reporting on lines selected due to the rule.


## Selectors
A selector defines a match criteria which is compared against each line read from the log_source to determine if the rule should be triggered.

Rules must define 1 or more selectors.

Each selector may include any of the following attributes:
| Attribute | Domain | Required | Description
|--- | --- |--- | --
|type| a selector | yes | Determines which of the selectors is being configured.
|description | String | no |A description of the selector used when reporting a matched line.
|risk | critical \| high \| medium \| low \| none | no | The risk level of lines selected by the rule. The risk is use to sort reporting so as to highlight high risk events in the logs. The default risk level is critical.


A number of selectors are supported

| Name | Description
|--- |--
|contains | matches if line contains all of the the passed strings.
|creditcard| matches if the line contains a credit card.
|one_of| matches if the line contains at least one of the passed strings.
|regex | Matches if some part of the line matches the regular expression.



### contains
The `contains` selector will select a line if it matches all of the match strings.
|Attribute| Domain | Description
|--| --|--
|match| Array of Strings | If all of the strings match, the line is selected.
|exclude| Array of Strings | if a line is selected via `match` but it also matches all of the strings in `exclude` then it will be deselected.
|insensitive| true \| false | if true then a case insenstive match is performed. Defaults to case-sensitive matches.

```yaml
rules:
    - rule:
      name: error high
      description: A high error was detected
      selectors:
        - selector:
          type: contains
          description: The line contained the words 'error' and 'high'
          match: ["error", "high"]
          risk: critical
    
``` 
### credit_card
The credit card selector scans lines for credit card numbers

The creditcard selector has no unique attributes.

```yaml
rules:
    - rule:
      name: creditcard
      description: Scans for credit cards 
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected in a log file
          risk: critical
          
```          

### one_of
The `one_of` selector will select a line if it matches ANY of the match strings.
|Attribute| Domain | Description
|--| --| --
|match| Array of Strings | If any of the strings are found in the line it will  be selected.
|exclude| Array of Strings | if a line is selected via `match` but it also matches any of the strings in `exclude` then it will be deselected.
|insensitive| true \| false | if true then a case insenstive match is performed. Defaults to case-sensitive matches.

```yaml
rules:
    - rule:
      name: error or warning
      description: A  error or warning was detected
      selectors:
        - selector:
          type: one_of
          description: The line contained the words 'error' or 'warning'
          match: ["error", "warning"]
          risk: high
          
``` 

### regex
The `regex` selector will select a line if it matches all of the match regular expressions.
|Attribute| Domain | Description
|--| --|-
|match| Array of regex expressions | If all of the regexes match, the line is selected.
|exclude| Array of Strings | if a line is selected via `match` but it also matches all of the regexes in `exclude` then it will be deselected.

```yaml
rules:
    - rule:
      name: error high
      description: A high error was detected
      selectors:
        - selector:
          type: contains
          description: The line contained the words 'error:' or 'error;'
          match: ["error[:;]"]
          risk: critical
          
``` 

## Reporting
At the end of each scan a report is generated and an email is sent to each log_source's report_to email address.
If `report_on_success` is true then an email is sent on both a successful scan (no lines were selected) as well as a failed scan.

By default each Rule that is triggered (by one of its selectors selecting a line) will result in a line in the report.

You can adjust this by using the `group_by` attribute in a log_source.
The `group_by` attrbute will instead count the no. of lines that triggered the report and then randomly select a max of four lines to include in the report along with the total no. of lines.



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

## Publish docker container
To publish the Batman docker container to docker.hub run:

```bash
docker build -f batman/docker/Dockerfile
docker push noojee/batman
```



# Installation

Copy the batman exe generated via the build process onto the target system.

We suggest that you place it under the /opt directory.

Once you have copied the exe run:

```bash
./batman install
```

## db_path
Batman uses a Hive database for storing the file checksums. By default this stored in:
```
<HOME>/.batman/hive
```

You can change the directory that is used for the hive database during the install.

```bash
./batman install --db_path=/opt/batman/hive
```
The db_path directory will be created by the installer. 

If you change the location of the hive database after running a baseline then you must re-run the baseline or copy the hive database to the new location.

## rule_path
Batman is configured via a settings file called `batman.yaml`. By default this is stored in:
```
<HOME>/.batman/batman.yaml
```

You can modify this path during the install by passing the --rule_path flag:

```bash
./batman install --rulepath=/opt/batman/batman.yaml
```

This will cause a settings.yaml file to be created in the same directory as the batman executable which will be read each time batman starts.




For installation into a Docker container see the Docker section below.
# Configuration

The batman batman.yaml contains a number of global settings that you need to configure
for it to operate correctly,

| key | domain | description
|---  |---------------  |--
| email_server_host | ip or fqdn | the smtp server used to send email notifications
|email_server_port | integer | the port no. the smtp server listens on.
|email_from_address| email address | The email address used in the 'from' when sending notifications.
|db_path | path | Path to directory where we will store the file integrity hive database. Becareful to exclude this path from scanning. By default batman excludes the db_path directory but if you are using a Docker volume/mount or a symlink batman may not realize it is the same directory.
|send_email_on_fail| true \| false | If set then an email will be sent if failure is detected.
|send_email_on_success| true \| false | If set then an email will be sent even for successful runs.
|email_fail_to_address| email address| The email address to send failure notices to.
|email_success_to_address| email address| The email address to send success notices to.
|report_to| Email | yes | The email address to send the result of this scan to.
|report_on_success| true \| false | no |If true then we report a sucessful scan as well as failed scans.



You can configure the set of directories that are scanned by editing the
default batman.yaml file.

The batman.yaml file is located at:

```~/.batman/batman.yaml```.

## Default batman.yaml

The default batman.yaml contains:

```yaml
send_email_on_fail: false
send_email_on_success: false

email_server_host: localhost
email_server_port: 25
email_from_address: scanner@mydomain.com
email_fail_to_address: failed.scan@mydomain.com
email_success_to_address: successful.scan@mydomain.com
db_path: ~/batman/hive
scan_byte_limit: 25000000

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

In the batman.yaml located at:

```~/.batman/batman.yaml```

You can add the following settings.

| Field | domain | default | description |
| ----- | ------ | ------- | ----------- |
| send_email_on_fail| true or false | false | If true then an email is sent after every failed scan |
| send_email_on_success| true or false | false |  If true then an email is sent after every succesful scan|
| email_server_host| fqdn | localhost | The fully qualified domain name of the smtp server |
| email_server_port| integer | 25 | The port no. of the smtp server |
| email_from_address| email address| none | The email address to use as the 'from' address when sending emails
| email_fail_to_address| email address | none | The email address send failed scans to
| email_success_to_address| email address | email_fail_to_address | The email address to send succesful scans to. If not set then we use the email_fail_to_address address.



# Scheduling scans

You should schedule scans on at least a weekly basis and preferably daily.

## cron
To create a schedule use cron

Edit /etc/conron.d/crontab.daily

To run the scan every day at 10:30 pm add the following line:

0 30 22 * * *  someuser  /opt/batman scan > /var/log/batman.log


## Batman cron
batman also includes a built in cron process. 

This is primarily designed for docker containers that only allow a single 
executable to run.

There is an example Dockerfile in the examples directory.

To build and publish the Dockerfile

```bash
tool/build.dart
```

# Docker
The Batman projects publishes a docker container to docker.hub that you can run out of the box.

You will likely want to customise the rules used by batman.

The following is an example docker-compose you can use to launch the batman docker container:

```yaml

version: '2.4'

volumes:
  batman: null

services:
  batman:
    container_name: batman
    image: noojee/batman:latest
    restart: on-failure
    environment:
      TZ: ${TZ:-Australia/Melbourne}
    volumes:
      - batman:/opt/batman
      - /:/scandir:ro
      - /opt/batman/rules:/etc/batman
    logging:
      driver: "journald"

```

The above docker-compose mounts the host file system read only (ro) into the container as /scandir

The resource/docker_batman.yaml file contains an example set of entities to scan from the /scandir

```yaml
logPath: /var/log/batman.log

email_server_host: localhost
email_server_port: 25
email_from_address: scanner@mydomain.com
report_on_success: false
report_to: failed.scan@mydomain.com

file_integrity:
  scan_byte_limit: 25000000
  db_path: /batman/data/hive

  # List of file system entities (directories and/or files) that are to be included in the baseline
  entities:
    - /scandir/

  # List of file system entities (files or directories) that are to be excluded from the baseline.
  # These entities must be children of one of the directories
  # listed in the entities section.
  exclusions:
    - /scandir/dev
    - /scandir/sys
    - /scandir/proc
    - /scandir/tmp
    - /scandir/run
    - /scandir/home
    ... 
```

## Customising batman.yaml

Batman will install a default batman.yaml into /etc/batman/batman.yaml.

The default rules provide a reasonable set of entities for running a baseline/integrity scan however the rules
for log scanning need to be customized.

If you need to customize the rules then you either need to build your own docker image with your own rules or you need to have
the docker container mount a host volume so your rules are editable from the host and persisted.

The first time the Batman Docker container runs it will look for the batman.yaml file in /etc/batman/batman.yaml. If it doesn't exists then it will
create a default batman.yaml file.

To customize the rules you need to mount a host volume into /etc/batman.
Using docker-compose:

```yaml
version: '3.1'

volumes:
  batman: null

services:
  batman:
    container_name: batman
    image: noojee/batman:latest
    restart: on-failure
    environment:
      TZ: ${TZ:-Australia/Melbourne}
    volumes:
     - batman/hive:/data/hive       
     - batman/etc:/etc/batman  
     - /:/scandir:ro     
    logging:
      driver: "local"      
```

You can now edit the batman.yaml on the docker volume `batman/etc/batman/batman.yaml`.

You need to restart the docker container for the changes to take affect.





