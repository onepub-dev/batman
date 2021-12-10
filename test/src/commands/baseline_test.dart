import 'dart:io';

import 'package:batman/src/batman_settings.dart';
import 'package:batman/src/commands/baseline.dart';
import 'package:batman/src/hive/model/file_checksum.dart';
import 'package:batman/src/parsed_args.dart';
import 'package:crclib/catalog.dart';
import 'package:dcli/dcli.dart';
import 'package:test/test.dart';

void main() {
  test('baseline ...', () {
    ParsedArgs.withArgs(['--quiet', '--insecure']);
    BaselineCommand().run();
  });

  test('hash performance', () {
    BatmanSettings.load();
    withTempFile((largeFile) {
      try {
        createLargeFile(largeFile);
        now();
        FileChecksum.contentChecksum(largeFile);
        now();
        waitForEx(File(largeFile).openRead().transform(Crc32()).single);
        now();
        // ignore: avoid_catches_without_on_clauses
      } catch (e) {
        print(e);
      }
    });
  });

  test('crc32 test - existing file', () {
    try {
      waitForEx(
          File(join(HOME, '.bashrc')).openRead().transform(Crc32()).single);
      // ignore: avoid_catches_without_on_clauses
    } catch (e) {
      print(e);
    }
  });
}

void now() {
  print(DateTime.now());
}

void createLargeFile(String largeFile) {
  for (var i = 0; i < 100000; i++) {
    largeFile.append('*' * 1000);
  }
}
