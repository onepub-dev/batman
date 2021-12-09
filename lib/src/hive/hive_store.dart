import 'package:dcli/dcli.dart';
import 'package:hive/hive.dart';

import '../batman_settings.dart';
import '../commands/baseline.dart';
import 'boxes.dart';
import 'model/file_checksum.dart';

class HiveStore {
  factory HiveStore() => _self;
  HiveStore._init() {
    Hive
      ..init(BatmanSettings().pathToDb)
      ..registerAdapter<FileChecksum>(FileChecksumAdapter());
  }

  static final HiveStore _self = HiveStore._init();

  void addChecksum(String pathTo, int checksum) {
    final _checksum = FileChecksum(pathTo, checksum);

    final checksums = Boxes().fileChecksums;
    waitForEx(checksums.put(_checksum.pathHash, _checksum));
  }

  FileChecksum? getCheckSum(String pathTo) {
    final checksums = Boxes().fileChecksums;

    return waitForEx(checksums.get(pathTo));
  }

  void deleteBaseline() {
    final checksums = Boxes().fileChecksums;

    waitForEx(checksums.deleteFromDisk());

    /// need to reopen the box after deleting it.
    Boxes().openChecksums();
  }

  /// If [clear] is true then we also clear the [mark] field
  /// on the [FileChecksum]
  CheckSumCompareResult compareCheckSum(String pathTo, int checksum,
      {required bool clear}) {
    final existing = getCheckSum(pathTo);

    if (existing == null) {
      return CheckSumCompareResult.missing;
    }
    if (clear) {
      existing
        ..marked = false
        ..save();
    }

    if (simpleHash(pathTo) == checksum) {
      return CheckSumCompareResult.matching;
    } else {
      return CheckSumCompareResult.mismatch;
    }
  }

  /// Markes each checksum so that we can check that all files
  /// still exist after a scan.
  void mark() => waitForEx(_mark());

  Future<void> _mark() async {
    final checksums = Boxes().fileChecksums;
    for (final key in checksums.keys) {
      final checksum = await checksums.get(key);
      checksum!.marked = true;
      await checksum.save();
    }
  }

  /// Finds a list of checksums that didn't have their mark
  /// cleared during a scan meaning that they are no longer on disk.
  Stream<String> sweep() async* {
    final checksums = Boxes().fileChecksums;
    await for (final key
        in Stream<String>.fromIterable(checksums.keys as Iterable<String>)) {
      final checksum = await checksums.get(key);
      if (checksum!.marked == true) {
        yield checksum.pathTo;
      }
    }
  }
}

enum CheckSumCompareResult { missing, matching, mismatch }
