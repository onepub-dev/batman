import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import 'package:zone_di2/zone_di2.dart';

import '../batman_settings.dart';
import '../dependency_injection/tokens.dart';
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
  int run() => provide(<Token<LocalSettings>, LocalSettings>{
        localSettingsToken: LocalSettings.load()
      }, _run);

  int _run() {
    BatmanSettings.load();

    if (!Shell.current.isPrivilegedUser) {
      print('Please run batman with elevated priviliges.');
      return 1;
    }
    final pathToDb = BatmanSettings().pathToDb;
    final settings = inject(localSettingsToken);
    try {
      if (settings.hasLocalSettings) {
        print(orange('Found ${settings.pathToLocalSettings}'));
      }

      print('Hive path: $pathToDb');

      print('Hive files');
      find('*', workingDirectory: pathToDb).forEach(print);

      print('Baseline Files: ${HiveStore().checksumCount()}');

      BatmanSettings().validate();
    } on FileSystemException catch (_) {
      printerr(orange('Access denied to ${BatmanSettings().pathToDb}'));
    }

    print('Rules path: ${settings.rulePath}');
    return 1;
  }
}
