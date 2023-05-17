/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';
import 'package:zone_di2/zone_di2.dart';

import 'batman_settings.dart';
import 'dependency_injection/tokens.dart';
import 'email.dart';
import 'log.dart';
import 'parsed_args.dart';
import 'when.dart';

Future<int> scanner(
    Future<int> Function(
            BatmanSettings rules, String entity, String pathToInvalidFiles)
        action,
    {required String name,
    required String pathToInvalidFiles}) async {
  final args = ParsedArgs();
  final rules = BatmanSettings.load();
  if (rules.entities.isEmpty) {
    log(red('There were no entities in ${inject(localSettingsToken).rulePath}. '
        'Add at least one entity and try again'));
    log(red('$when $name failed'));
    return 1;
  }

  var directoriesScanned = 0;
  var filesScanned = 0;
  var failed = 0;
  var bytes = 0;
  Shell.current.withPrivileges(() async {
    log(blue('$when Running $name'));

    var filesWithinDirectoryCount = 0;

    for (final ruleEntity in rules.entities) {
      filesWithinDirectoryCount = 0;
      if (!exists(ruleEntity)) {
        logerr('The entity $ruleEntity defined in file_integrity.entities'
            ' does not exist.');
        continue;
      }
      if (isDirectory(ruleEntity)) {
        directoriesScanned++;
        if (!args.quiet && filesWithinDirectoryCount != 0) {
          log('');
        }

        find('*',
                workingDirectory: ruleEntity,
                types: [Find.directory, Find.file],
                includeHidden: true)
            .forEach((entity) async {
          if (rules.excluded(entity)) {
            return;
          }
          if (isFile(entity)) {
            final size = stat(entity).size;
            bytes += size;

            failed += await action(rules, entity, pathToInvalidFiles);
            filesScanned++;
            if (filesScanned % 100 == 0) {
              if (args.countMode) {
                overwriteLine(
                    'Processed: Directories $directoriesScanned Files: '
                    '$filesScanned Bytes: ${Format().bytesAsReadable(bytes)}');
              } else {
                overwriteLine(
                    '${properCase(name)}($filesWithinDirectoryCount): '
                    '$ruleEntity $entity ');
              }
            }

            filesWithinDirectoryCount++;
          } else {
            directoriesScanned++;
          }
        });
        overwriteLine('$name($filesWithinDirectoryCount): $ruleEntity done.');
      } else {
        failed += await action(rules, ruleEntity, pathToInvalidFiles);
      }
    }
  }, allowUnprivileged: true);

  if (!args.quiet) {
    log('');
  }

  if (failed > 0) {
    log(green('$when ${properCase(name)} completed with errors. '
        'Processed: Directories $directoriesScanned Files: '
        '$filesScanned Bytes: ${Format().bytesAsReadable(bytes)}'));

    await email(
        actionName: name,
        success: false,
        directories: directoriesScanned,
        files: filesScanned,
        failed: failed,
        pathToInvalidFiles: pathToInvalidFiles);
  } else {
    log(green('$when ${properCase(name)} complete. No errors. '
        'Processed: Directories $directoriesScanned Files: '
        '$filesScanned Bytes: ${Format().bytesAsReadable(bytes)}'));

    await email(
      actionName: name,
      success: true,
      directories: directoriesScanned,
      files: filesScanned,
    );
  }

  if (!args.quiet) {
    log('');
  }
  return 0;
}

String properCase(String word) =>
    '${word[0].toUpperCase()}${word.substring(1)}';

Future<void> email(
    {required bool success,
    required String actionName,
    required int directories,
    required int files,
    String? pathToInvalidFiles,
    int? failed}) async {
  final rules = BatmanSettings.load();
  if (success) {
    if (rules.sendEmailOnSuccess) {
      final toAddress = rules.emailSuccessToAddress.isEmpty
          ? rules.emailFailToAddress
          : rules.emailSuccessToAddress;
      if (toAddress.isEmpty) {
        logerr('Unable to send success email as the email_success_to_address '
            'has not be configured in batman.yaml');
        return;
      }
      await Email.sendEmail(
          'File Integrity Monitor Suceeded',
          '''
The file Integrity monitor $actionName $directories directories and $files files.
        ''',
          toAddress);
    }
  } else {
    if (rules.sendEmailOnFail) {
      final toAddress = rules.emailFailToAddress;
      if (toAddress.isEmpty) {
        logerr(
            'Unable to send success email as the email_fail_to_address has not '
            'be configured in batman.yaml');
        return;
      }
      await Email.sendEmail(
          'ALERT: File Integrity Monitor detected problems:',
          '''
The file Integrity monitor $actionName $directories directories and $files, detected $failed problems with the following files.

${read(pathToInvalidFiles!).toParagraph()}
        ''',
          toAddress);
    }
  }
}

class ScanException implements Exception {
  ScanException(this.message);
  String message;
}
