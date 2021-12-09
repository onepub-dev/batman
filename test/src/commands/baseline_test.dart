import 'dart:io';

import 'package:batman/src/commands/baseline.dart';
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
    withTempFile((largeFile) {
      try {
        createLargeFile(largeFile);
        now();
        calculateHash(largeFile);
        now();
        waitForEx(File(largeFile).openRead().transform(Crc32()).single);
        now();
        // ignore: avoid_catches_without_on_clauses
      } catch (e) {
        print(e);
      }
    });
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
