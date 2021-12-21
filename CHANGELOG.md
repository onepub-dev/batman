# 1.0.7
- incremented version no.
- Fixed a bug when running the integrity scan a second time from cron. Hive was not being re-initialised correctly.

# 1.0.6
- migrated to zone_di2
- first release
- change the default mount fo the dev compose to mount the local dir.
- Fixed the sweep process which had a cast problem.
- Fixed bugs in the integrity scanner which was using trying to access the hive store without hashng the path.
- Improved error messages when yaml is incorrect.

# 1.0.1
- Added support for sending an email after each scan.
- Fixed problem with primssions when deleting the hashes directory

## 1.0.0

- Initial version.
