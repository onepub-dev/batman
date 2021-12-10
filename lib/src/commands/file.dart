import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';

import '../batman_settings.dart';
import '../hive/hive_store.dart';
import '../hive/model/file_checksum.dart';

///
class FileCommand extends Command<void> {
  ///
  FileCommand();

  @override
  String get description => '''
Displays the status of a single file. Usage: batman file <path to file>''';

  @override
  String get name => 'file';

  @override
  void run() {
    BatmanSettings.load();

    if (argResults!.rest.length != 1) {
      printerr(red('You must pass the path to a file'));
      exit(1);
    }

    final path = argResults!.rest[0];

    print('');
    print(green('Checking $path'));

    final checksum = HiveStore().getCheckSum(path);

    if (exists(path) && !isFile(path)) {
      print(orange('The path is a directory which we do not baseline'));
      exit(1);
    }
    if (checksum == null) {
      print(orange('The path has not been baselined'));
    } else {
      print(magenta('Checksum:'));
      print('  Path To: ${checksum.pathTo}');
      print('  Path Key: ${checksum.key}');
      print('  Path Checksum: ${checksum.checksum}');
      print('  Marked: ${checksum.marked}');
    }

    if (!exists(path)) {
      print(orange('The path does not exist on disk'));
    } else {
      final contentChecksum = FileChecksum.contentChecksum(path);
      print(blue('File:'));
      print('  Path To: $path');
      print('  Path Hash: ${FileChecksum.calculateKey(path)}');
      print('  Path Checksum: $contentChecksum');
      print('  Path Size: ${waitForEx(File(path).length())}');

      print('');

      if (checksum != null) {
        if (checksum.checksum == contentChecksum) {
          print(green('File integrity is intact!'));
        } else {
          print(red('Warning: File integrity may have been compromised: '
              'content does not match baseline'));
        }
      }
    }
  }
}
