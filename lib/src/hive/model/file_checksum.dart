/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dcli/dcli.dart';
import 'package:hive/hive.dart';

import '../../batman_settings.dart';

part 'file_checksum.g.dart';

@HiveType(typeId: 1)
class FileChecksum extends HiveObject {
  FileChecksum(this.pathTo, this.checksum)
      : pathHash = calculateKey(pathTo),
        marked = false;

  /// A has of the [pathTo] which is less than the hive
  /// key limit of 256 chars.
  @HiveField(0)
  String pathHash;

  @HiveField(1)
  String pathTo;
  @HiveField(2)
  int checksum;

  /// Used by the mark and sweep process when scanning.
  @HiveField(3)
  bool marked;

  @override
  String toString() => '$pathTo: $checksum';

  static String calculateKey(String path) =>
      md5.convert(utf8.encode(path)).toString();

  /// Calculates the hash of the content of a file.
  /// We used to use:
  ///  calculateHash from dcli but it was rather slow
  static Future<int> contentChecksum(String pathToFile) async {
    if (stat(pathToFile).size == 0) {
      return 0;
    }

    final limit = BatmanSettings().scanByteLimit;

    // await File(pathToFile).openRead(0, limit).transform(Crc32()).single;

    final sum =
        await File(pathToFile).openRead(0, limit).reduce((previous, element) {
      var sum = 0;
      sum += previous.reduce((p, e) => p + e);
      if (element.isNotEmpty) {
        sum += element.reduce((p, e) => p + e);
      }
      return [sum];
    });

    return sum.first;
  }
}
