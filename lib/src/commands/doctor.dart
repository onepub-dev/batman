import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../hive/hive_store.dart';
import '../local_settings.dart';

///
class DoctorCommand extends Command<void> {
  ///
  DoctorCommand();

  @override
  String get description => 'Displays the Batman settings';

  @override
  String get name => 'doctor';

  @override
  void run() {
    BatmanSettings.load();

    final pathToDb = BatmanSettings().pathToDb;

    try {
      if (!isReadable(pathToDb)) {
        print('Please run batman with elevated priviliges.');
        exit(1);
      } else {
        find('*', workingDirectory: pathToDb).forEach((file) {
          if (!isReadable(file)) {
            print('Please run batman with elevated priviliges2.');
            exit(1);
          }
        });

        if (LocalSettings.hasLocalSettings) {
          print(orange('Found ${LocalSettings.pathToLocalSettings}'));
        }

        print('Hive path: $pathToDb');
        print('Baseline Files: ${HiveStore().checksumCount()}');

        BatmanSettings().validate();
      }
    } on FileSystemException catch (_) {
      printerr(orange('Access denied to ${BatmanSettings().pathToDb}'));
    }

    print('Rules path: ${LocalSettings().rulePath}');
  }
}
