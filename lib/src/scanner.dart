import 'dart:io';

import 'package:dcli/dcli.dart';

import 'batman_settings.dart';
import 'email.dart';
import 'log.dart';
import 'parsed_args.dart';
import 'when.dart';

void scanner(
    int Function(
            {required BatmanSettings rules,
            required String entity,
            required String pathToInvalidFiles})
        action,
    {required String name,
    required String pathToInvalidFiles}) {
  final args = ParsedArgs();
  final rules = BatmanSettings.load();
  if (rules.entities.isEmpty) {
    log(red('There were no entities in ${BatmanSettings.pathToRules}. '
        'Add at least one entity and try again'));
    log(red('$when $name failed'));
    exit(1);
  }

  var directoriesScanned = 0;
  var filesScanned = 0;
  var failed = 0;
  var bytes = 0;
  Shell.current.withPrivileges(() {
    log(blue('$when Running $name'));

    var filesWithinDirectoryCount = 0;

    for (final ruleEntity in rules.entities) {
      filesWithinDirectoryCount = 0;
      if (isDirectory(ruleEntity)) {
        directoriesScanned++;
        if (!args.quiet && filesWithinDirectoryCount != 0) {
          log('');
        }

        find('*',
                workingDirectory: ruleEntity,
                types: [Find.directory, Find.file],
                includeHidden: true)
            .forEach((entity) {
          if (rules.excluded(entity)) {
            return;
          }
          if (isFile(entity)) {
            final size = stat(entity).size;
            bytes += size;

            failed += action(
                rules: rules,
                entity: entity,
                pathToInvalidFiles: pathToInvalidFiles);
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
        failed += action(
            rules: rules,
            entity: ruleEntity,
            pathToInvalidFiles: pathToInvalidFiles);
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

    email(
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

    email(
      actionName: name,
      success: true,
      directories: directoriesScanned,
      files: filesScanned,
    );
  }

  if (!args.quiet) {
    log('');
  }
}

String properCase(String word) =>
    '${word[0].toUpperCase()}${word.substring(1)}';

void email(
    {required bool success,
    required String actionName,
    required int directories,
    required int files,
    String? pathToInvalidFiles,
    int? failed}) {
  final rules = BatmanSettings.load();
  if (success) {
    if (rules.sendEmailOnSuccess) {
      final toAddress = rules.emailSuccessToAddress.isEmpty
          ? rules.emailFailToAddress
          : rules.emailSuccessToAddress;
      if (toAddress.isEmpty) {
        logerr('Unable to send success email as the email_success_to_address '
            'has not be configured in rules.yaml');
        return;
      }
      Email.sendEmail(
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
            'be configured in rules.yaml');
        return;
      }
      Email.sendEmail(
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
