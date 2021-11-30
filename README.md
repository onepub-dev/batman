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

A rules.yaml may contain multiple rules, log_sources and selectors.

## Location of rules.yaml
By default batma will look for you rules.yaml file in `~/.batman/rules.yaml`.

You can change were batman searches for your rule path by setting an environment variable:

e.g.
```
export RULE_PATH="/etc/batman/rules.yaml"
```

If you are using docker then setting a the RULE_PATH enviroment variable in you docker or docker-compose file is the recommended approach.



The following example defines one log_source and two rules.

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

## Rules
Rules for log scan are built up from a number of components

* log_source
* rule
* selector

## log_source
A log source lets you define how to obtain a log file to be scanned.

Each log source may define one or more of the following common attributes:
| Attribute | Domain | Required | Description
|- |-|-|-
| type | file \| journald \| docker| yes |The type of log source
| top | integer | no | Controls how may of the reported matches are reported.
| description | string | yes | A description of the log source which is used when reporting matches.
|report_to| Email | yes | The email address to send the result of this scan to.
|report_on_success| true \| false | no |If true then we report a sucessful scan as well as failed scans.
| trim_prefix | regex | no |When reporting a match the line is trimmed upto and including the trim_prefix. If there is no trim_prefix or no part of the line matches the trim_prefix then the entire line will be reported.
|reset | String | no | Used to reset the counters and discared lines selected to the point where a log line matches the reset string. This is used by log_sources that are only interested in output since the last restart of the system.
|group_by|regex | Cause all selected lines to be grouped by the part of the line that matches the regular expression. See the section on [reporting](#reporting) for details.




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
The docker log source is able to read data from a docker log that was written to journal d.

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
      name: error high
      description: A high error was detected
      selectors:
        - selector:
          type: one_of
          description: The line contained the words 'error' and 'high'
          risk: critical
          
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
          description: The line contained the words 'error' and 'high'
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



# Installation

Copy the batman exe generated via the build process onto the target system.

We suggest that you place it under the /opt directory.

Once you have copied the exe run:

```bash
./batman install
```

# Configuration

The batman rules.yaml contains a number of global settings that you need to configure
for it to operate correctly,

| key | domain | description
|---  |---------------  |--
| email_server_host | ip or fqdn | the smtp server used to send email notifications
|email_server_port | integer | the port no. the smtp server listens on.
|email_from_address| email address | The email address used in the 'from' when sending notifications.
|hashes_path | path | Path to directory where we will store the file integrity hashses. Becareful to exclude this path from scanning or you will cause infinite recursion until you run out of disk. By default batman excludes its own hashes directory but if you are using a Docker volume/mount or a symlink batman may not realize it is the same directory.
|send_email_on_fail| true \| false | If set then an email will be sent if failure is detected.
|send_email_on_success| true \| false | If set then an email will be sent even for successful runs.
|email_fail_to_address| email address| The email address to send failure notices to.
|email_success_to_address| email address| The email address to send success notices to.




You can configure the set of directories that are scanned by editing the
default rules.yaml file.

The rules.yaml file is located at:

```~/.batman/rules.yaml```.


You can change were batman searches for your rule path by setting an environment variable:

e.g.
```
export RULE_PATH="/etc/batman/rules.yaml"
```

If you are using docker then setting a the RULE_PATH enviroment variable in you docker or docker-compose file is the recommended approach.


## Default rules.yaml

The default rules.yaml contains:

```dart
send_email_on_fail: false
send_email_on_success: false

email_server_host: localhost
email_server_port: 25
email_from_address: scanner@mydomain.com
email_fail_to_address: failed.scan@mydomain.com
email_success_to_address: successful.scan@mydomain.com
hashes_path: /opt/batman/hashes

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
| send_email_on_fail| true or false | false | If true then an email is sent after every failed scan |
| send_email_on_success| true or false | false |  If true then an email is sent after every succesful scan|
| email_server_host| fqdn | localhost | The fully qualified domain name of the smtp server |
| email_server_port| integer | 25 | The port no. of the smtp server |
| email_from_address| email address| none | The email address to use as the 'from' address when sending emails
| email_fail_to_address| email address | none | The email address send failed scans to
| email_success_to_address| email address | email_fail_to_address | The email address to send succesful scans to. If not set then we use the email_fail_to_address address.


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
tool/docker_push.dart
```

# Docker
The Batman projects publishs a docker container to docker.hub that you can run out of the box.

The following is an example docker-compose you can use to launch the batman docker container:

```docker-compose

version: '2.4'

volumes:
  batman: null

services:
  batman:
    container_name: batman
    image: noojee/batman:latest
    restart: on-failure
    environment:
      EMAIL_ADDRESS: support@mye.online
      RULE_PATH: /etc/batman/rules.yaml
    volumes:
      - batman:/opt/batman
      - /:/scandir:ro
      - /opt/batman/rules:/etc/batman
    logging:
      driver: "journald"

```

The above docker-compose mounts the host file system read only (ro) into the container as /scandir







