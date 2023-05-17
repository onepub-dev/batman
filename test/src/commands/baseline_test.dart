/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:batman/src/batman_settings.dart';
import 'package:batman/src/hive/model/file_checksum.dart';
import 'package:crclib/catalog.dart';
import 'package:dcli/dcli.dart' hide run;
import 'package:test/test.dart';

void main() {
  test('hash performance', () async {
    BatmanSettings.load();
    await withTempFile((largeFile) async {
      try {
        createLargeFile(largeFile);
        now();
        await FileChecksum.contentChecksum(largeFile);
        now();
        await File(largeFile).openRead().transform(Crc32()).single;
        now();
        // ignore: avoid_catches_without_on_clauses
      } catch (e) {
        print(e);
      }
    });
  });

  test('crc32 test - existing file', () async {
    try {
      await File(join(HOME, '.bashrc')).openRead().transform(Crc32()).single;
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
