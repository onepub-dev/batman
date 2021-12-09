import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:hive/hive.dart';

part 'file_checksum.g.dart';

@HiveType(typeId: 1)
class FileChecksum extends HiveObject {
  FileChecksum(this.pathTo, this.checksum)
      : pathHash = md5.convert(utf8.encode(pathTo)).toString(),
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
}
