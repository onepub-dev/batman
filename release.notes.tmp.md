# 1.0.4
- removed dep overrides.
- wip
- Fixed a bug where constantly re-open the store.
- wip
- updated to dcli_scritps 1.1.4
- removed local dcli_script path dep.
- removed path deps.
- upraded to correct version of dcli_core.
- release prep
- Fixed the sweep process which had a cast problem.
- cleanup of output
- Fixed bugs in the integrity scanner which was using trying to access the hive store without hashng the path.
- wip
- wip
- Added a version option.
- Improved error messages when yaml is incorrect.
- revised and document all of the global settings.
- removed bad log file.
- ignored large sample log file.
- removed big file
- First working version of log scanning.
- Released 1.0.1.
- Begining of experimenting with the concept of defining re-usable rules. Each log source can then just select what rules should be applied.
- Added new command to trigger a scan of logs.
- grammar
- renamed pcifim to batman
- All unit tests successful.
- wip - core log analysis engine is now running. Writing unit tests for each selector.
- working dockerfile.
- re-implemented baseline and scan using a common scanner.
- removed hardcoded verbose logging.
- wip docker
- wip docker
- Updated scan and baseline to include hidden files.
- Updated the baseline and scanner to exclue the .pcifim directory to stop infinite recusion.
- tweaked the readme.
- Added extra logging to the rules so we can see where rules are being loaded from and how many rules.
- documented the new cron option.
- wip docker file.
- repaced adjusted rules.yaml
- removed an invalid line from the defaults rules.yaml
- upgraded to dcli 1.12.4
- hardcoded verbose
- added global versbose option
- removed dep overrdie for dcli
- re packed the rules.yaml
- Utilised the new dcli option allowUnpriviliged with withPriviliges to allow the --unsecure switch to work without convuluted logic.
- upgraded to dcli 1.12.3 to fix a bug under docker where the user was unknown.
- upgraded to dcli 1.12.1
- Added ability to schedule the scan using the new cron command: pcifim cron "30 22 * * *"
- Updated rules based on google gcp-cos-basic-fim scan.sh settings.
- Released 1.0.0.
- Released 1.0.0.
- Released 1.0.1.
- ignored .failed_tracker
- Added support for sending an email after each scan.
- Fixed problem with primssions when deleting the hashes.
- version 1.0
- Initial commit

# 1.0.1
- Added support for sending an email after each scan.
- Fixed problem with primssions when deleting the hashes directory

## 1.0.0

- Initial version.