/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:hive/hive.dart';

import '../batman_settings.dart';
import 'boxes.dart';
import 'model/file_checksum.dart';

class HiveStore {
  factory HiveStore() {
    if (!_self._initialised) {
      Hive
        ..init(BatmanSettings().pathToDb)
        ..registerAdapter<FileChecksum>(FileChecksumAdapter(), override: true);
      _self._initialised = true;
    }

    return _self;
  }
  HiveStore._init();

  static final HiveStore _self = HiveStore._init();

  Future<void> close() async {
    await Hive.close();
  }

  bool _initialised = false;

  Future<void> addChecksum(String pathTo, int checksum) async {
    final _checksum = FileChecksum(pathTo, checksum);

    final checksums = await Boxes().fileChecksumBox;
    await checksums.put(_checksum.pathHash, _checksum);
  }

  Future<FileChecksum?> getCheckSum(String pathTo) async {
    final checksums = await Boxes().fileChecksumBox;

    return checksums.get(FileChecksum.calculateKey(pathTo));
  }

  /// returns the no. of checksumed files
  Future<int> checksumCount() async => (await Boxes().fileChecksumBox).length;

  Future<void> deleteBaseline() async {
    final checksums = await Boxes().fileChecksumBox;

    await checksums.deleteFromDisk();
  }

  /// If [clear] is true then we also clear the [mark] field
  /// on the [FileChecksum]
  Future<CheckSumCompareResult> compareCheckSum(String pathTo, int checksum,
      {required bool clear}) async {
    final existing = await getCheckSum(pathTo);

    if (existing == null) {
      return CheckSumCompareResult.missing;
    }
    if (clear) {
      existing.marked = false;
      await existing.save();
    }
    final contentChecksum = await FileChecksum.contentChecksum(pathTo);
    if (contentChecksum == checksum) {
      return CheckSumCompareResult.matching;
    } else {
      return CheckSumCompareResult.mismatch;
    }
  }

  /// Markes each checksum so that we can check that all files
  /// still exist after a scan.
  Future<void> mark() async => _mark();

  Future<void> _mark() async {
    final checksums = await Boxes().fileChecksumBox;
    for (final key in checksums.keys) {
      final checksum = await checksums.get(key);
      checksum!.marked = true;
      await checksum.save();
    }
  }

  /// Finds a list of checksums that didn't have their mark
  /// cleared during a scan meaning that they are no longer on disk.
  Stream<String> sweep() async* {
    final checksums = await Boxes().fileChecksumBox;
    await for (final key in Stream<dynamic>.fromIterable(checksums.keys)) {
      final checksum = await checksums.get(key);
      if (checksum!.marked == true) {
        yield checksum.pathTo;
      }
    }
  }

  Future<void> compact() async {
    await (await Boxes().fileChecksumBox).compact();
  }
}

enum CheckSumCompareResult { missing, matching, mismatch }
